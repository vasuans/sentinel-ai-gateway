"""
Sentinel Gateway Middleware.
Authentication, structured logging, and request processing middleware.
"""
import json
import logging
import sys
import time
import uuid
from contextvars import ContextVar
from datetime import datetime
from typing import Any, Callable, Dict, Optional

from fastapi import HTTPException, Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.types import ASGIApp

from app.config import Settings, get_settings
from app.metrics import metrics_collector
from app.redis_client import redis_client

# Context variable for request tracking
request_id_ctx: ContextVar[str] = ContextVar("request_id", default="")
agent_id_ctx: ContextVar[str] = ContextVar("agent_id", default="")


class StructuredLogger:
    """
    JSON structured logger compatible with Datadog/Splunk.
    """
    
    def __init__(self, name: str, level: int = logging.INFO):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        
        # Remove existing handlers
        self.logger.handlers = []
        
        # Add JSON handler
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JSONFormatter())
        self.logger.addHandler(handler)
    
    def _enrich(self, extra: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich log with context variables."""
        enriched = {
            "request_id": request_id_ctx.get(""),
            "agent_id": agent_id_ctx.get(""),
            "timestamp": datetime.utcnow().isoformat(),
            "service": "sentinel-gateway",
        }
        enriched.update(extra)
        return enriched
    
    def info(self, message: str, **kwargs) -> None:
        self.logger.info(message, extra={"extra": self._enrich(kwargs)})
    
    def warning(self, message: str, **kwargs) -> None:
        self.logger.warning(message, extra={"extra": self._enrich(kwargs)})
    
    def error(self, message: str, **kwargs) -> None:
        self.logger.error(message, extra={"extra": self._enrich(kwargs)})
    
    def debug(self, message: str, **kwargs) -> None:
        self.logger.debug(message, extra={"extra": self._enrich(kwargs)})
    
    def critical(self, message: str, **kwargs) -> None:
        self.logger.critical(message, extra={"extra": self._enrich(kwargs)})


class JSONFormatter(logging.Formatter):
    """JSON log formatter for Datadog/Splunk compatibility."""
    
    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        
        # Add extra fields if present
        if hasattr(record, "extra"):
            log_entry.update(record.extra)
        
        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        
        return json.dumps(log_entry, default=str)


def setup_structured_logging(level: str = "INFO") -> None:
    """Configure structured logging for the application."""
    log_level = getattr(logging, level.upper(), logging.INFO)
    
    # Configure root logger
    root = logging.getLogger()
    root.setLevel(log_level)
    root.handlers = []
    
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JSONFormatter())
    root.addHandler(handler)
    
    # Reduce noise from third-party libraries
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


# Global structured logger
structured_logger = StructuredLogger("sentinel")


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware for request/response logging with structured JSON output.
    """
    
    def __init__(self, app: ASGIApp, settings: Optional[Settings] = None):
        super().__init__(app)
        self.settings = settings or get_settings()
    
    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        # Generate request ID
        request_id = str(uuid.uuid4())
        request_id_ctx.set(request_id)
        
        # Add request ID to response headers
        start_time = time.perf_counter()
        
        # Log request
        structured_logger.info(
            "Request received",
            method=request.method,
            path=request.url.path,
            query=str(request.query_params),
            client_ip=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )
        
        try:
            response = await call_next(request)
            
            # Calculate latency
            latency_ms = (time.perf_counter() - start_time) * 1000
            
            # Add headers
            response.headers["X-Request-ID"] = request_id
            response.headers["X-Processing-Time-Ms"] = f"{latency_ms:.2f}"
            
            # Log response
            structured_logger.info(
                "Request completed",
                status_code=response.status_code,
                latency_ms=latency_ms,
            )
            
            return response
            
        except Exception as e:
            latency_ms = (time.perf_counter() - start_time) * 1000
            
            structured_logger.error(
                "Request failed",
                error=str(e),
                error_type=type(e).__name__,
                latency_ms=latency_ms,
            )
            raise


class AuthenticationMiddleware(BaseHTTPMiddleware):
    """
    API key authentication middleware for agent requests.
    Validates Bearer tokens with agent_sk_ prefix.
    """
    
    # Endpoints that don't require authentication
    PUBLIC_PATHS = {
        "/",
        "/health",
        "/health/ready",
        "/health/live",
        "/metrics",
        "/docs",
        "/openapi.json",
        "/redoc",
    }
    
    def __init__(self, app: ASGIApp, settings: Optional[Settings] = None):
        super().__init__(app)
        self.settings = settings or get_settings()
        # In production, these would come from a database
        self._valid_keys: Dict[str, Dict[str, Any]] = {
            "agent_sk_test_key_12345678901234567890": {
                "agent_id": "test_agent",
                "name": "Test Agent",
                "permissions": ["*"],
                "rate_limit": 1000,
            },
            "agent_sk_demo_key_abcdefghijklmnopqrst": {
                "agent_id": "demo_agent",
                "name": "Demo Agent",
                "permissions": ["database_query", "api_call"],
                "rate_limit": 500,
            },
        }
    
    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        # Skip auth for public paths
        if request.url.path in self.PUBLIC_PATHS:
            return await call_next(request)
        
        # Skip auth for path prefixes
        if request.url.path.startswith("/docs") or request.url.path.startswith("/redoc"):
            return await call_next(request)
        
        # Extract API key from Authorization header
        auth_header = request.headers.get("Authorization", "")
        
        if not auth_header.startswith("Bearer "):
            return JSONResponse(
                status_code=401,
                content={
                    "error": "unauthorized",
                    "message": "Missing or invalid Authorization header",
                    "detail": "Expected: Authorization: Bearer agent_sk_...",
                },
            )
        
        api_key = auth_header[7:]  # Remove "Bearer " prefix
        
        # Validate key format
        if not api_key.startswith(self.settings.api_key_prefix):
            return JSONResponse(
                status_code=401,
                content={
                    "error": "unauthorized",
                    "message": "Invalid API key format",
                    "detail": f"API key must start with '{self.settings.api_key_prefix}'",
                },
            )
        
        if len(api_key) < self.settings.api_key_min_length:
            return JSONResponse(
                status_code=401,
                content={
                    "error": "unauthorized",
                    "message": "Invalid API key",
                    "detail": "API key is too short",
                },
            )
        
        # Validate key against store
        agent_info = self._valid_keys.get(api_key)
        if not agent_info:
            structured_logger.warning(
                "Authentication failed",
                reason="invalid_key",
                key_prefix=api_key[:20] + "...",
            )
            return JSONResponse(
                status_code=401,
                content={
                    "error": "unauthorized",
                    "message": "Invalid API key",
                },
            )
        
        # Set agent context
        agent_id_ctx.set(agent_info["agent_id"])
        
        # Store agent info in request state
        request.state.agent_id = agent_info["agent_id"]
        request.state.agent_name = agent_info["name"]
        request.state.agent_permissions = agent_info["permissions"]
        
        structured_logger.debug(
            "Authentication successful",
            agent_id=agent_info["agent_id"],
        )
        
        return await call_next(request)
    
    def register_api_key(
        self,
        api_key: str,
        agent_id: str,
        name: str,
        permissions: list,
        rate_limit: int = 1000,
    ) -> bool:
        """Register a new API key (for testing/admin purposes)."""
        if not api_key.startswith(self.settings.api_key_prefix):
            return False
        
        self._valid_keys[api_key] = {
            "agent_id": agent_id,
            "name": name,
            "permissions": permissions,
            "rate_limit": rate_limit,
        }
        return True


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Rate limiting middleware using Redis.
    """
    
    EXCLUDED_PATHS = {"/", "/health", "/health/ready", "/health/live", "/metrics"}
    
    def __init__(self, app: ASGIApp, settings: Optional[Settings] = None):
        super().__init__(app)
        self.settings = settings or get_settings()
    
    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        # Skip rate limiting for excluded paths
        if request.url.path in self.EXCLUDED_PATHS:
            return await call_next(request)
        
        # Get agent ID from context
        agent_id = agent_id_ctx.get("")
        if not agent_id:
            return await call_next(request)
        
        # Check rate limit
        try:
            is_allowed, remaining = await redis_client.check_rate_limit(agent_id)
            
            if not is_allowed:
                metrics_collector.record_rate_limited(agent_id)
                structured_logger.warning(
                    "Rate limit exceeded",
                    agent_id=agent_id,
                    remaining=remaining,
                )
                
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": "rate_limit_exceeded",
                        "message": "Too many requests",
                        "retry_after": self.settings.rate_limit_window_seconds,
                    },
                    headers={
                        "Retry-After": str(self.settings.rate_limit_window_seconds),
                        "X-RateLimit-Limit": str(self.settings.rate_limit_requests),
                        "X-RateLimit-Remaining": "0",
                    },
                )
            
            # Process request
            response = await call_next(request)
            
            # Add rate limit headers
            response.headers["X-RateLimit-Limit"] = str(self.settings.rate_limit_requests)
            response.headers["X-RateLimit-Remaining"] = str(remaining)
            
            return response
            
        except Exception as e:
            structured_logger.error(
                "Rate limiting error",
                error=str(e),
            )
            # Fail open on rate limit errors
            return await call_next(request)


class ErrorHandlingMiddleware(BaseHTTPMiddleware):
    """
    Global error handling middleware.
    Converts exceptions to structured JSON responses.
    """
    
    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        try:
            return await call_next(request)
            
        except HTTPException as e:
            return JSONResponse(
                status_code=e.status_code,
                content={
                    "error": "http_error",
                    "message": e.detail,
                    "status_code": e.status_code,
                },
            )
            
        except ValueError as e:
            structured_logger.warning(
                "Validation error",
                error=str(e),
            )
            return JSONResponse(
                status_code=400,
                content={
                    "error": "validation_error",
                    "message": str(e),
                },
            )
            
        except Exception as e:
            structured_logger.error(
                "Unhandled exception",
                error=str(e),
                error_type=type(e).__name__,
            )
            return JSONResponse(
                status_code=500,
                content={
                    "error": "internal_server_error",
                    "message": "An unexpected error occurred",
                    "request_id": request_id_ctx.get(""),
                },
            )
