"""
Sentinel: Enterprise AI Governance Gateway
Main FastAPI Application

A production-ready, scalable middleware platform that governs multiple concurrent AI Agents.
Acts as a "Zero-Trust" proxy between Agents and their tools (Databases, APIs, SaaS).
"""
import time
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse

from app.circuit_breaker import (
    ApprovalService,
    CircuitBreaker,
    approval_service,
    circuit_breaker,
    get_approval_service,
    get_circuit_breaker,
)
from app.config import GatewayMode, Settings, get_settings
from app.database import AuditLogEntry, Database, database, get_database
from app.metrics import metrics_collector
from app.middleware import (
    AuthenticationMiddleware,
    ErrorHandlingMiddleware,
    RateLimitMiddleware,
    RequestLoggingMiddleware,
    setup_structured_logging,
    structured_logger,
)
from app.models import (
    ActionType,
    AgentRequest,
    ApprovalResponse,
    ApprovalStatus,
    DecisionType,
    GatewayResponse,
    HealthStatus,
    MetricsSummary,
    PolicyEvaluationResult,
    PolicyRule,
    RiskLevel,
)
from app.policy_engine import PolicyEngine, get_policy_engine, policy_engine
from app.redis_client import RedisClient, get_redis, redis_client

# Application startup time
START_TIME = time.time()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager for startup and shutdown."""
    settings = get_settings()
    
    # Setup structured logging
    setup_structured_logging(settings.log_level)
    structured_logger.info(
        "Starting Sentinel Gateway",
        version=settings.app_version,
        mode=settings.gateway_mode.value,
    )
    
    # Initialize Redis
    try:
        await redis_client.connect()
        structured_logger.info("Redis connected")
    except Exception as e:
        structured_logger.error("Redis connection failed", error=str(e))
        # Continue without Redis (degraded mode)
    
    # Initialize PostgreSQL
    try:
        await database.connect()
        structured_logger.info("PostgreSQL connected")
    except Exception as e:
        structured_logger.error("PostgreSQL connection failed", error=str(e))
        # Continue without database (audit logs disabled)
    
    # Initialize Policy Engine
    await policy_engine.initialize(redis_client)
    structured_logger.info("Policy Engine initialized")
    
    # Initialize Approval Service
    await approval_service.initialize(redis_client)
    structured_logger.info("Approval Service initialized")
    
    # Initialize Circuit Breaker
    await circuit_breaker.initialize(redis_client, approval_service)
    structured_logger.info("Circuit Breaker initialized")
    
    # Update initial metrics
    policies = await policy_engine.get_active_policies()
    metrics_collector.set_active_policies(len(policies))
    
    structured_logger.info(
        "Sentinel Gateway started successfully",
        active_policies=len(policies),
    )
    
    yield
    
    # Shutdown
    structured_logger.info("Shutting down Sentinel Gateway")
    
    await approval_service.shutdown()
    await redis_client.disconnect()
    await database.disconnect()
    
    structured_logger.info("Sentinel Gateway shutdown complete")


# Create FastAPI application
app = FastAPI(
    title="Sentinel: Enterprise AI Governance Gateway",
    description="""
    A production-ready, scalable middleware platform that governs multiple concurrent AI Agents.
    
    ## Features
    - **Zero-Trust Proxy**: Validates all agent requests before forwarding to tools
    - **Dynamic Policy Engine**: Real-time policy updates via Redis
    - **PII Detection & Sanitization**: Automatic detection and masking of sensitive data
    - **Circuit Breaker**: Shadow mode for safe onboarding, enforce mode for production
    - **Human-in-the-Loop**: Approval workflows for high-risk actions
    - **Full Observability**: Prometheus metrics, structured JSON logging
    """,
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# Add middleware (order matters - last added = first executed)
app.add_middleware(ErrorHandlingMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(AuthenticationMiddleware)
app.add_middleware(RequestLoggingMiddleware)


# ==================== Health Endpoints ====================

@app.get("/", tags=["Health"])
async def root():
    """Root endpoint."""
    return {
        "service": "Sentinel AI Governance Gateway",
        "version": "1.0.0",
        "status": "operational",
        "docs": "/docs",
    }


@app.get("/health", response_model=HealthStatus, tags=["Health"])
async def health_check():
    """Comprehensive health check."""
    settings = get_settings()
    
    redis_connected = await redis_client.is_connected()
    postgres_connected = await database.is_connected()
    
    # Update system metrics
    metrics_collector.update_system_status(
        gateway_mode=1 if settings.gateway_mode == GatewayMode.SHADOW else 0,
        redis_connected=redis_connected,
        postgres_connected=postgres_connected,
    )
    
    status = "healthy" if redis_connected and postgres_connected else "degraded"
    
    return HealthStatus(
        status=status,
        version=settings.app_version,
        gateway_mode=settings.gateway_mode.value,
        redis_connected=redis_connected,
        postgres_connected=postgres_connected,
        uptime_seconds=time.time() - START_TIME,
    )


@app.get("/health/ready", tags=["Health"])
async def readiness_check():
    """Kubernetes readiness probe."""
    redis_connected = await redis_client.is_connected()
    postgres_connected = await database.is_connected()
    
    if not redis_connected or not postgres_connected:
        raise HTTPException(
            status_code=503,
            detail="Service not ready - dependencies unavailable",
        )
    
    return {"status": "ready"}


@app.get("/health/live", tags=["Health"])
async def liveness_check():
    """Kubernetes liveness probe."""
    return {"status": "alive"}


# ==================== Metrics Endpoint ====================

@app.get("/metrics", tags=["Observability"])
async def prometheus_metrics():
    """Prometheus metrics endpoint."""
    return PlainTextResponse(
        content=metrics_collector.generate_metrics().decode("utf-8"),
        media_type=metrics_collector.get_content_type(),
    )


# ==================== Gateway API ====================

@app.post(
    "/api/v1/gateway/evaluate",
    response_model=GatewayResponse,
    tags=["Gateway"],
    summary="Evaluate an agent request",
    description="""
    Evaluate an agent request against the policy engine.
    
    The request will be:
    1. Authenticated via API key
    2. Rate limited
    3. Scanned for PII (sanitized before logging)
    4. Evaluated against active policies
    5. Processed by the circuit breaker
    
    Returns one of:
    - **200**: Request allowed
    - **202**: Request pending human approval
    - **403**: Request denied by policy
    """,
)
async def evaluate_request(
    request: Request,
    agent_request: AgentRequest,
    policy_engine_dep: PolicyEngine = Depends(get_policy_engine),
    circuit_breaker_dep: CircuitBreaker = Depends(get_circuit_breaker),
    db: Database = Depends(get_database),
    redis: RedisClient = Depends(get_redis),
):
    """Evaluate an agent request through the governance gateway."""
    start_time = time.perf_counter()
    settings = get_settings()
    
    # Get agent info from authenticated request
    agent_id = getattr(request.state, "agent_id", agent_request.agent_id)
    
    try:
        # Step 1: Evaluate against policy engine
        evaluation = await policy_engine_dep.evaluate(agent_request)
        
        # Record policy evaluation metrics
        metrics_collector.record_policy_evaluation_time(
            evaluation.evaluation_time_ms / 1000
        )
        
        for rule_id in evaluation.matched_rules:
            metrics_collector.record_policy_match(
                rule_id, agent_request.action_type.value
            )
        
        # Record PII detection
        if evaluation.pii_detected:
            metrics_collector.record_pii_detection(
                agent_id, evaluation.pii_fields
            )
        
        # Step 2: Process through circuit breaker
        response = await circuit_breaker_dep.process(agent_request, evaluation)
        
        # Step 3: Record metrics
        latency_seconds = time.perf_counter() - start_time
        
        metrics_collector.record_request(
            agent_id=agent_id,
            action_type=agent_request.action_type.value,
            decision=response.decision.value,
            latency_seconds=latency_seconds,
            risk_score=evaluation.risk_score,
        )
        
        if evaluation.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            metrics_collector.record_high_risk_request(
                agent_id, agent_request.action_type.value, evaluation.risk_level.value
            )
        
        if response.decision == DecisionType.DENY:
            metrics_collector.record_blocked_request(
                agent_id,
                agent_request.action_type.value,
                evaluation.denial_reasons[0] if evaluation.denial_reasons else "policy",
            )
        elif response.decision == DecisionType.SHADOW_LOGGED:
            metrics_collector.record_shadow_logged(
                agent_id, agent_request.action_type.value
            )
        elif response.decision == DecisionType.ALLOW:
            metrics_collector.record_approved_request(
                agent_id, agent_request.action_type.value
            )
        
        # Record latency to Redis for percentile calculations
        await redis.record_latency(latency_seconds * 1000)
        
        # Step 4: Write audit log
        audit_entry = AuditLogEntry(
            request_id=agent_request.request_id,
            agent_id=agent_id,
            action_type=agent_request.action_type,
            target_resource=agent_request.target_resource,
            decision=response.decision,
            risk_score=evaluation.risk_score,
            risk_level=evaluation.risk_level,
            matched_rules=evaluation.matched_rules,
            pii_detected=evaluation.pii_detected,
            pii_fields=evaluation.pii_fields,
            gateway_mode=settings.gateway_mode.value,
            sanitized_request=evaluation.sanitized_request or {},
            response_status=response.status,
            processing_time_ms=latency_seconds * 1000,
            client_ip=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )
        
        await db.log_audit(audit_entry)
        
        # Step 5: Return appropriate response
        if response.decision == DecisionType.PENDING_APPROVAL:
            return JSONResponse(
                status_code=202,
                content=response.model_dump(mode="json"),
            )
        elif response.decision == DecisionType.DENY:
            return JSONResponse(
                status_code=403,
                content=response.model_dump(mode="json"),
            )
        
        return response
        
    except Exception as e:
        structured_logger.error(
            "Gateway evaluation error",
            error=str(e),
            request_id=str(agent_request.request_id),
        )
        raise HTTPException(status_code=500, detail=str(e))


# ==================== Policy Management ====================

@app.get(
    "/api/v1/policies",
    response_model=List[PolicyRule],
    tags=["Policies"],
    summary="List all active policies",
)
async def list_policies(
    policy_engine_dep: PolicyEngine = Depends(get_policy_engine),
):
    """Get all active policies from the cache."""
    policies = await policy_engine_dep.get_active_policies()
    
    # Update metrics
    metrics_collector.set_active_policies(len(policies))
    
    return policies


@app.get(
    "/api/v1/policies/{rule_id}",
    response_model=PolicyRule,
    tags=["Policies"],
    summary="Get a specific policy",
)
async def get_policy(
    rule_id: str,
    policy_engine_dep: PolicyEngine = Depends(get_policy_engine),
):
    """Get a specific policy by ID."""
    policy = await policy_engine_dep.get_policy(rule_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    return policy


@app.post(
    "/api/v1/policies",
    response_model=PolicyRule,
    status_code=201,
    tags=["Policies"],
    summary="Create a new policy",
)
async def create_policy(
    policy: PolicyRule,
    policy_engine_dep: PolicyEngine = Depends(get_policy_engine),
    db: Database = Depends(get_database),
):
    """Create or update a policy in the cache."""
    success = await policy_engine_dep.add_policy(policy)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to create policy")
    
    # Log policy change
    await db.log_policy_change(
        policy_id=policy.rule_id,
        action="created",
        new_value=policy.model_dump(mode="json"),
    )
    
    structured_logger.info(
        "Policy created",
        rule_id=policy.rule_id,
        name=policy.name,
    )
    
    return policy


@app.delete(
    "/api/v1/policies/{rule_id}",
    tags=["Policies"],
    summary="Delete a policy",
)
async def delete_policy(
    rule_id: str,
    policy_engine_dep: PolicyEngine = Depends(get_policy_engine),
    db: Database = Depends(get_database),
):
    """Delete a policy from the cache."""
    # Get existing policy for audit
    existing = await policy_engine_dep.get_policy(rule_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Policy not found")
    
    success = await policy_engine_dep.remove_policy(rule_id)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to delete policy")
    
    # Log policy change
    await db.log_policy_change(
        policy_id=rule_id,
        action="deleted",
        old_value=existing.model_dump(mode="json"),
    )
    
    structured_logger.info("Policy deleted", rule_id=rule_id)
    
    return {"status": "deleted", "rule_id": rule_id}


# ==================== Approval Management ====================

@app.get(
    "/api/v1/approvals/{approval_id}",
    tags=["Approvals"],
    summary="Get approval status",
)
async def get_approval_status(
    approval_id: UUID,
    approval_service_dep: ApprovalService = Depends(get_approval_service),
):
    """Get the status of a pending approval."""
    status = await approval_service_dep.get_approval_status(approval_id)
    if not status:
        raise HTTPException(status_code=404, detail="Approval not found")
    return status


@app.post(
    "/api/v1/approvals/{approval_id}/decision",
    response_model=ApprovalResponse,
    tags=["Approvals"],
    summary="Submit approval decision",
)
async def submit_approval_decision(
    approval_id: UUID,
    approved: bool,
    approver_id: Optional[str] = None,
    reason: Optional[str] = None,
    approval_service_dep: ApprovalService = Depends(get_approval_service),
    db: Database = Depends(get_database),
):
    """Submit an approval or denial decision."""
    response = await approval_service_dep.process_approval_decision(
        approval_id=approval_id,
        approved=approved,
        approver_id=approver_id,
        reason=reason,
    )
    
    if not response:
        raise HTTPException(status_code=404, detail="Approval not found or expired")
    
    # Get original approval for logging
    approval_data = await approval_service_dep.get_approval_status(approval_id)
    
    # Log approval decision
    await db.log_approval(
        approval_id=approval_id,
        request_id=UUID(approval_data["request_id"]) if approval_data else approval_id,
        agent_id=approval_data.get("agent_id", "unknown") if approval_data else "unknown",
        action_type=approval_data.get("action_type", "unknown") if approval_data else "unknown",
        risk_score=approval_data.get("risk_score", 0.0) if approval_data else 0.0,
        status=response.status.value,
        approver_id=approver_id,
        reason=reason,
        decided_at=response.approved_at,
    )
    
    structured_logger.info(
        "Approval decision recorded",
        approval_id=str(approval_id),
        approved=approved,
        approver_id=approver_id,
    )
    
    return response


# ==================== Gateway Mode Management ====================

@app.get("/api/v1/gateway/mode", tags=["Gateway"])
async def get_gateway_mode(
    circuit_breaker_dep: CircuitBreaker = Depends(get_circuit_breaker),
):
    """Get current gateway mode."""
    return {
        "mode": circuit_breaker_dep.get_mode().value,
        "description": (
            "Shadow mode: unsafe actions are logged but NOT blocked"
            if circuit_breaker_dep.get_mode() == GatewayMode.SHADOW
            else "Enforce mode: unsafe actions are blocked"
        ),
    }


@app.put("/api/v1/gateway/mode", tags=["Gateway"])
async def set_gateway_mode(
    mode: GatewayMode,
    circuit_breaker_dep: CircuitBreaker = Depends(get_circuit_breaker),
):
    """Change gateway mode at runtime."""
    old_mode = circuit_breaker_dep.get_mode()
    await circuit_breaker_dep.set_mode(mode)
    
    structured_logger.info(
        "Gateway mode changed",
        old_mode=old_mode.value,
        new_mode=mode.value,
    )
    
    return {
        "status": "updated",
        "old_mode": old_mode.value,
        "new_mode": mode.value,
    }


# ==================== Audit Logs ====================

@app.get("/api/v1/audit/logs", tags=["Audit"])
async def get_audit_logs(
    agent_id: Optional[str] = Query(None),
    action_type: Optional[str] = Query(None),
    decision: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Database = Depends(get_database),
):
    """Query audit logs with filters."""
    logs = await db.get_audit_logs(
        agent_id=agent_id,
        action_type=action_type,
        decision=decision,
        risk_level=risk_level,
        limit=limit,
        offset=offset,
    )
    return {"logs": logs, "count": len(logs), "limit": limit, "offset": offset}


@app.get("/api/v1/audit/stats", tags=["Audit"])
async def get_audit_stats(
    db: Database = Depends(get_database),
):
    """Get aggregate audit statistics."""
    return await db.get_audit_stats()


# ==================== Rate Limit Info ====================

@app.get("/api/v1/rate-limit", tags=["Gateway"])
async def get_rate_limit_info(
    request: Request,
    redis: RedisClient = Depends(get_redis),
):
    """Get rate limit information for the current agent."""
    agent_id = getattr(request.state, "agent_id", "unknown")
    return await redis.get_rate_limit_info(agent_id)


# ==================== Metrics Summary ====================

@app.get("/api/v1/metrics/summary", response_model=MetricsSummary, tags=["Observability"])
async def get_metrics_summary(
    redis: RedisClient = Depends(get_redis),
    policy_engine_dep: PolicyEngine = Depends(get_policy_engine),
):
    """Get a summary of key metrics."""
    latency_percentiles = await redis.get_latency_percentiles()
    policies = await policy_engine_dep.get_active_policies()
    
    return MetricsSummary(
        total_requests=await redis.get_metric("total_requests"),
        blocked_requests=await redis.get_metric("blocked_requests"),
        approved_requests=await redis.get_metric("approved_requests"),
        pending_approvals=await redis.get_metric("pending_approvals"),
        shadow_logged=await redis.get_metric("shadow_logged"),
        avg_latency_ms=latency_percentiles.get("avg", 0.0),
        p95_latency_ms=latency_percentiles.get("p95", 0.0),
        p99_latency_ms=latency_percentiles.get("p99", 0.0),
        pii_detections=await redis.get_metric("pii_detections"),
        active_policies=len(policies),
        uptime_seconds=metrics_collector.get_uptime(),
    )


if __name__ == "__main__":
    import uvicorn
    
    settings = get_settings()
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        workers=settings.workers,
        reload=settings.debug,
    )
