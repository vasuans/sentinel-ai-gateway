"""
Sentinel Gateway Metrics Module.
Prometheus-compatible metrics collection and exposure.
"""
import time
from typing import Any, Callable, Dict

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

# ==================== Request Metrics ====================

REQUEST_COUNT = Counter(
    "sentinel_requests_total",
    "Total number of requests processed",
    ["agent_id", "action_type", "decision"],
)

REQUEST_LATENCY = Histogram(
    "sentinel_request_latency_seconds",
    "Request latency in seconds",
    ["action_type"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0),
)

BLOCKED_REQUESTS = Counter(
    "sentinel_blocked_requests_total",
    "Total number of blocked requests",
    ["agent_id", "action_type", "reason"],
)

APPROVED_REQUESTS = Counter(
    "sentinel_approved_requests_total",
    "Total number of approved requests",
    ["agent_id", "action_type"],
)

PENDING_APPROVALS = Gauge(
    "sentinel_pending_approvals",
    "Current number of pending approvals",
)

SHADOW_LOGGED = Counter(
    "sentinel_shadow_logged_total",
    "Total number of requests logged in shadow mode",
    ["agent_id", "action_type"],
)

# ==================== Risk Metrics ====================

RISK_SCORE = Histogram(
    "sentinel_risk_score",
    "Distribution of risk scores",
    ["action_type"],
    buckets=(0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0),
)

HIGH_RISK_REQUESTS = Counter(
    "sentinel_high_risk_requests_total",
    "Total number of high-risk requests",
    ["agent_id", "action_type", "risk_level"],
)

# ==================== PII Metrics ====================

PII_DETECTIONS = Counter(
    "sentinel_pii_detections_total",
    "Total number of PII detections",
    ["entity_type"],
)

REQUESTS_WITH_PII = Counter(
    "sentinel_requests_with_pii_total",
    "Total number of requests containing PII",
    ["agent_id"],
)

# ==================== Policy Metrics ====================

ACTIVE_POLICIES = Gauge(
    "sentinel_active_policies",
    "Number of active policies",
)

POLICY_MATCHES = Counter(
    "sentinel_policy_matches_total",
    "Total number of policy matches",
    ["rule_id", "action_type"],
)

POLICY_EVALUATION_TIME = Histogram(
    "sentinel_policy_evaluation_seconds",
    "Time spent evaluating policies",
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5),
)

# ==================== System Metrics ====================

UPTIME = Gauge(
    "sentinel_uptime_seconds",
    "Gateway uptime in seconds",
)

GATEWAY_MODE = Gauge(
    "sentinel_gateway_mode",
    "Current gateway mode (0=ENFORCE, 1=SHADOW)",
)

REDIS_CONNECTED = Gauge(
    "sentinel_redis_connected",
    "Redis connection status (1=connected, 0=disconnected)",
)

POSTGRES_CONNECTED = Gauge(
    "sentinel_postgres_connected",
    "PostgreSQL connection status (1=connected, 0=disconnected)",
)

# ==================== Rate Limiting Metrics ====================

RATE_LIMITED_REQUESTS = Counter(
    "sentinel_rate_limited_requests_total",
    "Total number of rate-limited requests",
    ["agent_id"],
)

RATE_LIMIT_REMAINING = Gauge(
    "sentinel_rate_limit_remaining",
    "Remaining rate limit for agent",
    ["agent_id"],
)


class MetricsCollector:
    """
    Centralized metrics collection and reporting.
    """
    
    def __init__(self):
        self._start_time = time.time()
    
    def record_request(
        self,
        agent_id: str,
        action_type: str,
        decision: str,
        latency_seconds: float,
        risk_score: float,
    ) -> None:
        """Record metrics for a processed request."""
        REQUEST_COUNT.labels(
            agent_id=agent_id,
            action_type=action_type,
            decision=decision,
        ).inc()
        
        REQUEST_LATENCY.labels(action_type=action_type).observe(latency_seconds)
        RISK_SCORE.labels(action_type=action_type).observe(risk_score)
    
    def record_blocked_request(
        self,
        agent_id: str,
        action_type: str,
        reason: str,
    ) -> None:
        """Record a blocked request."""
        BLOCKED_REQUESTS.labels(
            agent_id=agent_id,
            action_type=action_type,
            reason=reason[:50],  # Truncate long reasons
        ).inc()
    
    def record_approved_request(
        self,
        agent_id: str,
        action_type: str,
    ) -> None:
        """Record an approved request."""
        APPROVED_REQUESTS.labels(
            agent_id=agent_id,
            action_type=action_type,
        ).inc()
    
    def record_shadow_logged(
        self,
        agent_id: str,
        action_type: str,
    ) -> None:
        """Record a shadow-logged request."""
        SHADOW_LOGGED.labels(
            agent_id=agent_id,
            action_type=action_type,
        ).inc()
    
    def record_high_risk_request(
        self,
        agent_id: str,
        action_type: str,
        risk_level: str,
    ) -> None:
        """Record a high-risk request."""
        HIGH_RISK_REQUESTS.labels(
            agent_id=agent_id,
            action_type=action_type,
            risk_level=risk_level,
        ).inc()
    
    def record_pii_detection(
        self,
        agent_id: str,
        entity_types: list,
    ) -> None:
        """Record PII detection."""
        REQUESTS_WITH_PII.labels(agent_id=agent_id).inc()
        for entity_type in entity_types:
            PII_DETECTIONS.labels(entity_type=entity_type).inc()
    
    def record_policy_match(
        self,
        rule_id: str,
        action_type: str,
    ) -> None:
        """Record a policy match."""
        POLICY_MATCHES.labels(
            rule_id=rule_id,
            action_type=action_type,
        ).inc()
    
    def record_policy_evaluation_time(self, seconds: float) -> None:
        """Record policy evaluation time."""
        POLICY_EVALUATION_TIME.observe(seconds)
    
    def set_active_policies(self, count: int) -> None:
        """Update active policies count."""
        ACTIVE_POLICIES.set(count)
    
    def set_pending_approvals(self, count: int) -> None:
        """Update pending approvals count."""
        PENDING_APPROVALS.set(count)
    
    def record_rate_limited(self, agent_id: str) -> None:
        """Record a rate-limited request."""
        RATE_LIMITED_REQUESTS.labels(agent_id=agent_id).inc()
    
    def set_rate_limit_remaining(self, agent_id: str, remaining: int) -> None:
        """Update remaining rate limit for agent."""
        RATE_LIMIT_REMAINING.labels(agent_id=agent_id).set(remaining)
    
    def update_system_status(
        self,
        gateway_mode: int,
        redis_connected: bool,
        postgres_connected: bool,
    ) -> None:
        """Update system status gauges."""
        UPTIME.set(time.time() - self._start_time)
        GATEWAY_MODE.set(gateway_mode)
        REDIS_CONNECTED.set(1 if redis_connected else 0)
        POSTGRES_CONNECTED.set(1 if postgres_connected else 0)
    
    def get_uptime(self) -> float:
        """Get current uptime in seconds."""
        return time.time() - self._start_time
    
    def generate_metrics(self) -> bytes:
        """Generate Prometheus metrics output."""
        return generate_latest()
    
    def get_content_type(self) -> str:
        """Get Prometheus content type."""
        return CONTENT_TYPE_LATEST


# Global metrics collector
metrics_collector = MetricsCollector()


def get_metrics_collector() -> MetricsCollector:
    """Get the global metrics collector."""
    return metrics_collector


def timed(metric_name: str = None) -> Callable:
    """
    Decorator to time function execution.
    Usage: @timed("my_operation")
    """
    def decorator(func: Callable) -> Callable:
        async def async_wrapper(*args, **kwargs):
            start = time.perf_counter()
            try:
                return await func(*args, **kwargs)
            finally:
                elapsed = time.perf_counter() - start
                if metric_name:
                    REQUEST_LATENCY.labels(action_type=metric_name).observe(elapsed)
        
        def sync_wrapper(*args, **kwargs):
            start = time.perf_counter()
            try:
                return func(*args, **kwargs)
            finally:
                elapsed = time.perf_counter() - start
                if metric_name:
                    REQUEST_LATENCY.labels(action_type=metric_name).observe(elapsed)
        
        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper
    
    return decorator
