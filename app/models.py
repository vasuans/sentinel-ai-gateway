"""
Sentinel Gateway Data Models.
Pydantic models for request/response validation and internal data structures.
"""
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator


class ActionType(str, Enum):
    """Types of actions agents can request."""
    DATABASE_QUERY = "database_query"
    DATABASE_WRITE = "database_write"
    API_CALL = "api_call"
    FILE_ACCESS = "file_access"
    PAYMENT = "payment"
    REFUND = "refund"
    USER_DATA_ACCESS = "user_data_access"
    ADMIN_ACTION = "admin_action"


class RiskLevel(str, Enum):
    """Risk classification levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DecisionType(str, Enum):
    """Policy decision types."""
    ALLOW = "allow"
    DENY = "deny"
    PENDING_APPROVAL = "pending_approval"
    SHADOW_LOGGED = "shadow_logged"


class AgentRequest(BaseModel):
    """Incoming request from an AI agent."""
    request_id: UUID = Field(default_factory=uuid4)
    agent_id: str = Field(..., min_length=1, max_length=128)
    action_type: ActionType
    target_resource: str = Field(..., min_length=1, max_length=512)
    parameters: Dict[str, Any] = Field(default_factory=dict)
    context: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    @field_validator('parameters', 'context', mode='before')
    @classmethod
    def ensure_dict(cls, v: Any) -> Dict[str, Any]:
        if v is None:
            return {}
        return v


class PolicyRule(BaseModel):
    """A single policy rule definition."""
    rule_id: str
    name: str
    description: Optional[str] = None
    action_types: List[ActionType]
    conditions: Dict[str, Any] = Field(default_factory=dict)
    risk_score_modifier: float = Field(default=0.0, ge=-1.0, le=1.0)
    enabled: bool = True
    priority: int = Field(default=100, ge=0, le=1000)
    
    class Config:
        json_schema_extra = {
            "example": {
                "rule_id": "refund_limit",
                "name": "Refund Amount Limit",
                "description": "Block refunds exceeding $500",
                "action_types": ["refund"],
                "conditions": {"max_amount": 500},
                "risk_score_modifier": 0.5,
                "enabled": True,
                "priority": 50
            }
        }


class PolicyEvaluationResult(BaseModel):
    """Result of evaluating a request against policies."""
    request_id: UUID
    decision: DecisionType
    risk_score: float = Field(ge=0.0, le=1.0)
    risk_level: RiskLevel
    matched_rules: List[str] = Field(default_factory=list)
    denial_reasons: List[str] = Field(default_factory=list)
    sanitized_request: Optional[Dict[str, Any]] = None
    pii_detected: bool = False
    pii_fields: List[str] = Field(default_factory=list)
    evaluation_time_ms: float = 0.0
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class GatewayResponse(BaseModel):
    """Response from the gateway to the agent."""
    request_id: UUID
    status: str
    decision: DecisionType
    message: str
    risk_level: RiskLevel
    approval_required: bool = False
    approval_id: Optional[UUID] = None
    forwarded: bool = False
    response_data: Optional[Dict[str, Any]] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ApprovalRequest(BaseModel):
    """Request sent to approval service for human-in-the-loop."""
    approval_id: UUID = Field(default_factory=uuid4)
    request_id: UUID
    agent_id: str
    action_type: ActionType
    target_resource: str
    risk_score: float
    risk_level: RiskLevel
    matched_rules: List[str]
    sanitized_parameters: Dict[str, Any]
    context: Dict[str, Any]
    requested_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None


class ApprovalStatus(str, Enum):
    """Status of an approval request."""
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


class ApprovalResponse(BaseModel):
    """Response from approval service."""
    approval_id: UUID
    status: ApprovalStatus
    approver_id: Optional[str] = None
    reason: Optional[str] = None
    approved_at: Optional[datetime] = None


class AuditLogEntry(BaseModel):
    """Audit log entry for persistence."""
    log_id: UUID = Field(default_factory=uuid4)
    request_id: UUID
    agent_id: str
    action_type: ActionType
    target_resource: str
    decision: DecisionType
    risk_score: float
    risk_level: RiskLevel
    matched_rules: List[str]
    pii_detected: bool
    pii_fields: List[str]
    gateway_mode: str
    sanitized_request: Dict[str, Any]
    response_status: str
    processing_time_ms: float
    client_ip: Optional[str] = None
    user_agent: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class HealthStatus(BaseModel):
    """Health check response."""
    status: str
    version: str
    gateway_mode: str
    redis_connected: bool
    postgres_connected: bool
    uptime_seconds: float
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class MetricsSummary(BaseModel):
    """Metrics summary for monitoring."""
    total_requests: int
    blocked_requests: int
    approved_requests: int
    pending_approvals: int
    shadow_logged: int
    avg_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float
    pii_detections: int
    active_policies: int
    uptime_seconds: float
