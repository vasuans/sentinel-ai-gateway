"""
Sentinel Gateway Circuit Breaker.
Implements shadow mode, enforcement mode, and human-in-the-loop approval workflows.
"""
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, Optional
from uuid import UUID, uuid4

import httpx

from app.config import GatewayMode, Settings, get_settings
from app.models import (
    ActionType,
    AgentRequest,
    ApprovalRequest,
    ApprovalResponse,
    ApprovalStatus,
    DecisionType,
    GatewayResponse,
    PolicyEvaluationResult,
    RiskLevel,
)
from app.redis_client import RedisClient

logger = logging.getLogger(__name__)


class ApprovalService:
    """
    Handles human-in-the-loop approval workflows.
    Sends webhooks to external approval service and tracks pending approvals.
    """
    
    def __init__(
        self,
        redis_client: Optional[RedisClient] = None,
        settings: Optional[Settings] = None,
    ):
        self.redis = redis_client
        self.settings = settings or get_settings()
        self._http_client: Optional[httpx.AsyncClient] = None
    
    async def initialize(self, redis_client: RedisClient) -> None:
        """Initialize the approval service."""
        self.redis = redis_client
        self._http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.settings.approval_webhook_timeout)
        )
        logger.info("Approval Service initialized")
    
    async def shutdown(self) -> None:
        """Cleanup resources."""
        if self._http_client:
            await self._http_client.aclose()
    
    async def request_approval(
        self,
        request: AgentRequest,
        evaluation: PolicyEvaluationResult,
    ) -> ApprovalRequest:
        """
        Create an approval request and send to external approval service.
        """
        approval_request = ApprovalRequest(
            approval_id=uuid4(),
            request_id=request.request_id,
            agent_id=request.agent_id,
            action_type=request.action_type,
            target_resource=request.target_resource,
            risk_score=evaluation.risk_score,
            risk_level=evaluation.risk_level,
            matched_rules=evaluation.matched_rules,
            sanitized_parameters=evaluation.sanitized_request.get("parameters", {}),
            context=request.context,
            expires_at=datetime.utcnow() + timedelta(hours=24),
        )
        
        # Store in Redis for tracking
        if self.redis:
            await self.redis.store_pending_approval(
                str(approval_request.approval_id),
                approval_request.model_dump(mode="json"),
                ttl=86400,  # 24 hours
            )
        
        # Send webhook to approval service
        await self._send_approval_webhook(approval_request)
        
        logger.info(
            f"Approval requested: {approval_request.approval_id} "
            f"for request {request.request_id}"
        )
        
        return approval_request
    
    async def _send_approval_webhook(self, approval: ApprovalRequest) -> bool:
        """Send approval request to external webhook."""
        if not self._http_client:
            logger.warning("HTTP client not initialized, skipping webhook")
            return False
        
        try:
            payload = {
                "event": "approval_requested",
                "approval_id": str(approval.approval_id),
                "request_id": str(approval.request_id),
                "agent_id": approval.agent_id,
                "action_type": approval.action_type.value,
                "target_resource": approval.target_resource,
                "risk_score": approval.risk_score,
                "risk_level": approval.risk_level.value,
                "matched_rules": approval.matched_rules,
                "parameters": approval.sanitized_parameters,
                "context": approval.context,
                "requested_at": approval.requested_at.isoformat(),
                "expires_at": approval.expires_at.isoformat() if approval.expires_at else None,
                "callback_url": f"/api/v1/approvals/{approval.approval_id}/decision",
            }
            
            response = await self._http_client.post(
                self.settings.approval_webhook_url,
                json=payload,
            )
            
            if response.status_code in (200, 201, 202):
                logger.info(f"Approval webhook sent successfully: {approval.approval_id}")
                return True
            else:
                logger.warning(
                    f"Approval webhook returned {response.status_code}: {response.text}"
                )
                return False
                
        except httpx.TimeoutException:
            logger.error(f"Approval webhook timeout for {approval.approval_id}")
            return False
        except httpx.RequestError as e:
            logger.error(f"Approval webhook failed for {approval.approval_id}: {e}")
            return False
    
    async def get_approval_status(self, approval_id: UUID) -> Optional[Dict[str, Any]]:
        """Get the status of a pending approval."""
        if self.redis:
            return await self.redis.get_pending_approval(str(approval_id))
        return None
    
    async def process_approval_decision(
        self,
        approval_id: UUID,
        approved: bool,
        approver_id: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> Optional[ApprovalResponse]:
        """Process an approval decision from the approval service."""
        if not self.redis:
            return None
        
        approval_data = await self.redis.get_pending_approval(str(approval_id))
        if not approval_data:
            logger.warning(f"Approval {approval_id} not found")
            return None
        
        response = ApprovalResponse(
            approval_id=approval_id,
            status=ApprovalStatus.APPROVED if approved else ApprovalStatus.DENIED,
            approver_id=approver_id,
            reason=reason,
            approved_at=datetime.utcnow(),
        )
        
        # Remove from pending
        await self.redis.delete_pending_approval(str(approval_id))
        
        logger.info(
            f"Approval {approval_id} {'approved' if approved else 'denied'} "
            f"by {approver_id or 'unknown'}"
        )
        
        return response


class CircuitBreaker:
    """
    Circuit breaker for controlling request flow based on policy evaluation.
    Supports shadow mode for enterprise onboarding.
    """
    
    def __init__(
        self,
        approval_service: Optional[ApprovalService] = None,
        settings: Optional[Settings] = None,
    ):
        self.approval_service = approval_service
        self.settings = settings or get_settings()
    
    async def initialize(
        self,
        redis_client: RedisClient,
        approval_service: ApprovalService,
    ) -> None:
        """Initialize the circuit breaker."""
        self.approval_service = approval_service
        logger.info(
            f"Circuit Breaker initialized in {self.settings.gateway_mode.value} mode"
        )
    
    async def process(
        self,
        request: AgentRequest,
        evaluation: PolicyEvaluationResult,
    ) -> GatewayResponse:
        """
        Process a request through the circuit breaker.
        Applies shadow/enforce mode logic and human-in-the-loop for high-risk requests.
        """
        # Determine base response
        response = GatewayResponse(
            request_id=request.request_id,
            status="success",
            decision=evaluation.decision,
            message="",
            risk_level=evaluation.risk_level,
            approval_required=False,
            forwarded=False,
        )
        
        # Handle based on decision
        if evaluation.decision == DecisionType.ALLOW:
            response.status = "success"
            response.message = "Request approved"
            response.forwarded = True
            
        elif evaluation.decision == DecisionType.SHADOW_LOGGED:
            # Shadow mode: log but don't block
            response.status = "success"
            response.message = (
                "Request approved (shadow mode - would be blocked in enforce mode)"
            )
            response.forwarded = True
            logger.warning(
                f"SHADOW MODE: Request {request.request_id} would be blocked. "
                f"Risk score: {evaluation.risk_score}, "
                f"Matched rules: {evaluation.matched_rules}"
            )
            
        elif evaluation.decision == DecisionType.PENDING_APPROVAL:
            # High risk but not max - request human approval
            if self.settings.gateway_mode == GatewayMode.SHADOW:
                # In shadow mode, log but allow
                response.status = "success"
                response.decision = DecisionType.SHADOW_LOGGED
                response.message = (
                    "Request approved (shadow mode - would require approval in enforce mode)"
                )
                response.forwarded = True
            else:
                # Request approval
                response.status = "pending"
                response.approval_required = True
                
                if self.approval_service:
                    approval = await self.approval_service.request_approval(
                        request, evaluation
                    )
                    response.approval_id = approval.approval_id
                    response.message = (
                        f"Request requires human approval. Approval ID: {approval.approval_id}"
                    )
                else:
                    response.message = "Request requires human approval"
                
                response.forwarded = False
                
        elif evaluation.decision == DecisionType.DENY:
            if self.settings.gateway_mode == GatewayMode.SHADOW:
                # Shadow mode: log but allow
                response.status = "success"
                response.decision = DecisionType.SHADOW_LOGGED
                response.message = (
                    f"Request approved (shadow mode - would be denied in enforce mode). "
                    f"Reasons: {'; '.join(evaluation.denial_reasons)}"
                )
                response.forwarded = True
                logger.warning(
                    f"SHADOW MODE: Request {request.request_id} denied. "
                    f"Reasons: {evaluation.denial_reasons}"
                )
            else:
                # Enforce mode: block
                response.status = "denied"
                response.message = f"Request denied: {'; '.join(evaluation.denial_reasons)}"
                response.forwarded = False
        
        return response
    
    def get_mode(self) -> GatewayMode:
        """Get current gateway mode."""
        return self.settings.gateway_mode
    
    async def set_mode(self, mode: GatewayMode) -> None:
        """
        Change the gateway mode at runtime.
        Note: In production, this would be persisted to Redis.
        """
        old_mode = self.settings.gateway_mode
        self.settings.gateway_mode = mode
        logger.info(f"Gateway mode changed from {old_mode.value} to {mode.value}")


class MockApprovalService:
    """
    Mock approval service for testing and development.
    Simulates an external approval workflow.
    """
    
    def __init__(self):
        self._pending: Dict[str, ApprovalRequest] = {}
    
    async def handle_approval_request(
        self,
        request: ApprovalRequest,
    ) -> Dict[str, Any]:
        """Handle incoming approval request (mock endpoint)."""
        self._pending[str(request.approval_id)] = request
        
        return {
            "status": "received",
            "approval_id": str(request.approval_id),
            "message": "Approval request received and queued for review",
            "estimated_wait_time": "15 minutes",
        }
    
    async def auto_approve(
        self,
        approval_id: str,
        delay_seconds: float = 0.0,
    ) -> ApprovalResponse:
        """Auto-approve a request after delay (for testing)."""
        if delay_seconds > 0:
            await asyncio.sleep(delay_seconds)
        
        return ApprovalResponse(
            approval_id=UUID(approval_id),
            status=ApprovalStatus.APPROVED,
            approver_id="mock_approver",
            reason="Auto-approved for testing",
            approved_at=datetime.utcnow(),
        )
    
    async def auto_deny(
        self,
        approval_id: str,
        reason: str = "Auto-denied for testing",
    ) -> ApprovalResponse:
        """Auto-deny a request (for testing)."""
        return ApprovalResponse(
            approval_id=UUID(approval_id),
            status=ApprovalStatus.DENIED,
            approver_id="mock_approver",
            reason=reason,
            approved_at=datetime.utcnow(),
        )
    
    def get_pending(self) -> Dict[str, ApprovalRequest]:
        """Get all pending approvals."""
        return self._pending.copy()


# Global instances
approval_service = ApprovalService()
circuit_breaker = CircuitBreaker()


async def get_approval_service() -> ApprovalService:
    """Dependency injection for approval service."""
    return approval_service


async def get_circuit_breaker() -> CircuitBreaker:
    """Dependency injection for circuit breaker."""
    return circuit_breaker
