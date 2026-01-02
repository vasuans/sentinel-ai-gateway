"""
Sentinel Gateway Policy Engine.
Dynamic policy evaluation with PII detection and sanitization.
"""
import copy
import logging
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from presidio_analyzer import AnalyzerEngine, RecognizerResult
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

from app.config import GatewayMode, Settings, get_settings
from app.models import (
    ActionType,
    AgentRequest,
    DecisionType,
    PolicyEvaluationResult,
    PolicyRule,
    RiskLevel,
)
from app.redis_client import RedisClient, get_redis

logger = logging.getLogger(__name__)


class PIISanitizer:
    """PII detection and sanitization using Microsoft Presidio."""
    
    # Entities to detect
    DEFAULT_ENTITIES = [
        "PERSON",
        "EMAIL_ADDRESS",
        "PHONE_NUMBER",
        "US_SSN",
        "CREDIT_CARD",
        "US_BANK_NUMBER",
        "IP_ADDRESS",
        "US_PASSPORT",
        "US_DRIVER_LICENSE",
        "CRYPTO",
        "IBAN_CODE",
        "MEDICAL_LICENSE",
        "URL",
    ]
    
    def __init__(self, entities: Optional[List[str]] = None):
        self.entities = entities or self.DEFAULT_ENTITIES
        self._analyzer: Optional[AnalyzerEngine] = None
        self._anonymizer: Optional[AnonymizerEngine] = None
        self._initialized = False
    
    def initialize(self) -> None:
        """Initialize Presidio engines (lazy loading for performance)."""
        if self._initialized:
            return
        
        try:
            from presidio_analyzer.nlp_engine import NlpEngineProvider
            
            # Configure to use en_core_web_sm model
            nlp_config = {
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
            }
            nlp_engine = NlpEngineProvider(nlp_configuration=nlp_config).create_engine()
            
            self._analyzer = AnalyzerEngine(nlp_engine=nlp_engine)
            self._anonymizer = AnonymizerEngine()
            self._initialized = True
            logger.info("PII Sanitizer initialized successfully with en_core_web_sm")
        except Exception as e:
            logger.error(f"Failed to initialize PII Sanitizer: {e}")
            # Create a fallback regex-based sanitizer
            self._initialized = True
    
    def analyze(self, text: str, language: str = "en") -> List[RecognizerResult]:
        """Analyze text for PII entities."""
        if not self._analyzer:
            return []
        
        try:
            return self._analyzer.analyze(
                text=text,
                language=language,
                entities=self.entities,
            )
        except Exception as e:
            logger.error(f"PII analysis failed: {e}")
            return []
    
    def sanitize_text(self, text: str, language: str = "en") -> Tuple[str, List[str]]:
        """
        Sanitize PII from text.
        Returns (sanitized_text, list_of_detected_entity_types).
        """
        if not text or not isinstance(text, str):
            return text, []
        
        if not self._analyzer or not self._anonymizer:
            # Fallback to regex-based sanitization
            return self._fallback_sanitize(text)
        
        try:
            results = self.analyze(text, language)
            
            if not results:
                return text, []
            
            # Get unique entity types
            detected_types = list(set(r.entity_type for r in results))
            
            # Anonymize with masking
            operators = {
                entity: OperatorConfig("mask", {"chars_to_mask": 8, "masking_char": "*"})
                for entity in detected_types
            }
            
            anonymized = self._anonymizer.anonymize(
                text=text,
                analyzer_results=results,
                operators=operators,
            )
            
            return anonymized.text, detected_types
            
        except Exception as e:
            logger.error(f"PII sanitization failed: {e}")
            return self._fallback_sanitize(text)
    
    def _fallback_sanitize(self, text: str) -> Tuple[str, List[str]]:
        """Fallback regex-based PII sanitization."""
        detected = []
        sanitized = text
        
        patterns = {
            "EMAIL_ADDRESS": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            "US_SSN": r'\b\d{3}-\d{2}-\d{4}\b',
            "PHONE_NUMBER": r'\b(?:\+1[-.]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
            "CREDIT_CARD": r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
            "IP_ADDRESS": r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        }
        
        for entity_type, pattern in patterns.items():
            if re.search(pattern, sanitized, re.IGNORECASE):
                detected.append(entity_type)
                sanitized = re.sub(pattern, "[REDACTED]", sanitized, flags=re.IGNORECASE)
        
        return sanitized, detected
    
    def sanitize_dict(
        self,
        data: Dict[str, Any],
        language: str = "en",
    ) -> Tuple[Dict[str, Any], List[str]]:
        """
        Recursively sanitize PII from a dictionary.
        Returns (sanitized_dict, list_of_all_detected_entity_types).
        """
        all_detected = []
        sanitized = self._sanitize_recursive(data, all_detected, language)
        return sanitized, list(set(all_detected))
    
    def _sanitize_recursive(
        self,
        data: Any,
        detected: List[str],
        language: str,
    ) -> Any:
        """Recursively process and sanitize data structures."""
        if isinstance(data, str):
            sanitized, types = self.sanitize_text(data, language)
            detected.extend(types)
            return sanitized
        
        elif isinstance(data, dict):
            return {
                key: self._sanitize_recursive(value, detected, language)
                for key, value in data.items()
            }
        
        elif isinstance(data, list):
            return [
                self._sanitize_recursive(item, detected, language)
                for item in data
            ]
        
        else:
            return data


class PolicyEngine:
    """
    Dynamic policy engine for evaluating agent requests.
    Loads policies from Redis and applies PII sanitization.
    """
    
    def __init__(
        self,
        redis_client: Optional[RedisClient] = None,
        settings: Optional[Settings] = None,
    ):
        self.redis = redis_client
        self.settings = settings or get_settings()
        self.pii_sanitizer = PIISanitizer()
        self._default_policies: List[PolicyRule] = []
        self._initialized = False
    
    async def initialize(self, redis_client: RedisClient) -> None:
        """Initialize the policy engine."""
        self.redis = redis_client
        self.pii_sanitizer.initialize()
        await self._load_default_policies()
        self._initialized = True
        logger.info("Policy Engine initialized")
    
    async def _load_default_policies(self) -> None:
        """Load default policies if none exist in cache."""
        self._default_policies = [
            PolicyRule(
                rule_id="refund_limit_500",
                name="Refund Amount Limit",
                description="Block refunds exceeding $500",
                action_types=[ActionType.REFUND],
                conditions={"max_amount": 500},
                risk_score_modifier=1.0,  # 1.0 = automatic deny when violated
                priority=10,
            ),
            PolicyRule(
                rule_id="payment_limit_10000",
                name="Payment Amount Limit",
                description="Require approval for payments over $10,000",
                action_types=[ActionType.PAYMENT],
                conditions={"max_amount": 10000},
                risk_score_modifier=0.85,  # 0.85 = requires human approval
                priority=20,
            ),
            PolicyRule(
                rule_id="admin_action_high_risk",
                name="Admin Actions High Risk",
                description="All admin actions are high risk",
                action_types=[ActionType.ADMIN_ACTION],
                conditions={},
                risk_score_modifier=0.85,  # 0.85 = requires human approval
                priority=5,
            ),
            PolicyRule(
                rule_id="user_data_access",
                name="User Data Access Control",
                description="User data access requires extra scrutiny",
                action_types=[ActionType.USER_DATA_ACCESS],
                conditions={"require_justification": True},
                risk_score_modifier=0.3,
                priority=30,
            ),
            PolicyRule(
                rule_id="database_write_protection",
                name="Database Write Protection",
                description="Database writes to protected tables",
                action_types=[ActionType.DATABASE_WRITE],
                conditions={"protected_tables": ["users", "payments", "credentials"]},
                risk_score_modifier=1.0,  # 1.0 = automatic deny
                priority=15,
            ),
            PolicyRule(
                rule_id="bulk_operation_limit",
                name="Bulk Operation Limit",
                description="Limit bulk operations affecting many records",
                action_types=[ActionType.DATABASE_WRITE, ActionType.DATABASE_QUERY],
                conditions={"max_affected_rows": 1000},
                risk_score_modifier=0.9,  # 0.9 = requires human approval
                priority=25,
            ),
        ]
        
        # Store default policies in Redis if empty
        if self.redis:
            existing = await self.redis.get_all_policies()
            if not existing:
                for policy in self._default_policies:
                    await self.redis.store_policy(policy)
                logger.info(f"Loaded {len(self._default_policies)} default policies")
    
    async def get_active_policies(self) -> List[PolicyRule]:
        """Get all active policies from cache."""
        if self.redis:
            policies = await self.redis.get_all_policies()
            if policies:
                return policies
        return self._default_policies
    
    async def evaluate(
        self,
        request: AgentRequest,
    ) -> PolicyEvaluationResult:
        """
        Evaluate a request against all active policies.
        Returns the evaluation result with risk assessment and decision.
        """
        start_time = time.perf_counter()
        
        # Initialize result
        result = PolicyEvaluationResult(
            request_id=request.request_id,
            decision=DecisionType.ALLOW,
            risk_score=0.0,
            risk_level=RiskLevel.LOW,
            matched_rules=[],
            denial_reasons=[],
            pii_detected=False,
            pii_fields=[],
        )
        
        try:
            # Step 1: Sanitize PII from request
            sanitized_params, pii_fields = self.pii_sanitizer.sanitize_dict(
                request.parameters
            )
            sanitized_context, context_pii = self.pii_sanitizer.sanitize_dict(
                request.context
            )
            
            all_pii_fields = list(set(pii_fields + context_pii))
            result.pii_detected = len(all_pii_fields) > 0
            result.pii_fields = all_pii_fields
            result.sanitized_request = {
                "parameters": sanitized_params,
                "context": sanitized_context,
                "agent_id": request.agent_id,
                "action_type": request.action_type.value,
                "target_resource": request.target_resource,
            }
            
            if result.pii_detected:
                logger.info(
                    f"PII detected in request {request.request_id}: {all_pii_fields}"
                )
            
            # Step 2: Get active policies
            policies = await self.get_active_policies()
            
            # Step 3: Evaluate each policy
            cumulative_risk = 0.0
            
            for policy in policies:
                if not policy.enabled:
                    continue
                
                if request.action_type not in policy.action_types:
                    continue
                
                # Evaluate policy conditions
                violation, reason = self._evaluate_conditions(
                    policy, request, sanitized_params
                )
                
                if violation:
                    result.matched_rules.append(policy.rule_id)
                    result.denial_reasons.append(reason)
                    cumulative_risk += policy.risk_score_modifier
            
            # Step 4: Calculate final risk score (clamped to 0-1)
            result.risk_score = min(1.0, max(0.0, cumulative_risk))
            
            # Step 5: Determine risk level
            result.risk_level = self._calculate_risk_level(result.risk_score)
            
            # Step 6: Determine decision based on risk score and mode
            result.decision = self._determine_decision(result.risk_score)
            
        except Exception as e:
            logger.error(f"Policy evaluation error: {e}")
            result.decision = DecisionType.DENY
            result.denial_reasons.append(f"Evaluation error: {str(e)}")
            result.risk_score = 1.0
            result.risk_level = RiskLevel.CRITICAL
        
        finally:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            result.evaluation_time_ms = elapsed_ms
        
        return result
    
    def _evaluate_conditions(
        self,
        policy: PolicyRule,
        request: AgentRequest,
        sanitized_params: Dict[str, Any],
    ) -> Tuple[bool, str]:
        """
        Evaluate policy conditions against request.
        Returns (is_violation, reason_message).
        """
        conditions = policy.conditions
        
        # Check max_amount condition
        if "max_amount" in conditions:
            amount = sanitized_params.get("amount", 0)
            if isinstance(amount, (int, float)) and amount > conditions["max_amount"]:
                return True, (
                    f"Amount ${amount} exceeds limit of ${conditions['max_amount']} "
                    f"({policy.name})"
                )
        
        # Check protected tables
        if "protected_tables" in conditions:
            target = request.target_resource.lower()
            for table in conditions["protected_tables"]:
                if table.lower() in target:
                    return True, (
                        f"Access to protected resource '{table}' ({policy.name})"
                    )
        
        # Check bulk operation limits
        if "max_affected_rows" in conditions:
            affected = sanitized_params.get("affected_rows", 0)
            limit = sanitized_params.get("limit", 0)
            count = max(affected, limit)
            if count > conditions["max_affected_rows"]:
                return True, (
                    f"Bulk operation affects {count} rows, "
                    f"limit is {conditions['max_affected_rows']} ({policy.name})"
                )
        
        # Check require_justification
        if conditions.get("require_justification"):
            justification = request.context.get("justification", "")
            if not justification or len(justification.strip()) < 10:
                return True, (
                    f"Justification required for this action ({policy.name})"
                )
        
        # If no specific conditions matched but policy matched action type,
        # still flag it for risk scoring (but not as violation)
        if not conditions:
            return True, f"Action type flagged by policy ({policy.name})"
        
        return False, ""
    
    def _calculate_risk_level(self, risk_score: float) -> RiskLevel:
        """Map risk score to risk level."""
        if risk_score >= 0.8:
            return RiskLevel.CRITICAL
        elif risk_score >= 0.5:
            return RiskLevel.HIGH
        elif risk_score >= 0.2:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW
    
    def _determine_decision(self, risk_score: float) -> DecisionType:
        """Determine decision based on risk score and gateway mode."""
        # Block if risk is at maximum
        if risk_score >= self.settings.risk_score_block_threshold:
            if self.settings.gateway_mode == GatewayMode.SHADOW:
                return DecisionType.SHADOW_LOGGED
            return DecisionType.DENY
        
        # Require approval for high-risk actions
        if risk_score >= self.settings.risk_score_approval_threshold:
            return DecisionType.PENDING_APPROVAL
        
        return DecisionType.ALLOW
    
    async def add_policy(self, policy: PolicyRule) -> bool:
        """Add or update a policy in the cache."""
        if self.redis:
            return await self.redis.store_policy(policy)
        return False
    
    async def remove_policy(self, rule_id: str) -> bool:
        """Remove a policy from the cache."""
        if self.redis:
            return await self.redis.delete_policy(rule_id)
        return False
    
    async def get_policy(self, rule_id: str) -> Optional[PolicyRule]:
        """Get a specific policy by ID."""
        if self.redis:
            return await self.redis.get_policy(rule_id)
        
        for policy in self._default_policies:
            if policy.rule_id == rule_id:
                return policy
        return None


# Global policy engine instance
policy_engine = PolicyEngine()


async def get_policy_engine() -> PolicyEngine:
    """Dependency injection for policy engine."""
    return policy_engine