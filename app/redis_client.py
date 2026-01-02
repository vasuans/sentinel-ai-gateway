"""
Sentinel Gateway Redis Client.
Handles policy caching, rate limiting, and session management.
"""
import json
import logging
from typing import Any, Dict, List, Optional

import redis.asyncio as redis
from redis.asyncio.connection import ConnectionPool

from app.config import Settings, get_settings
from app.models import PolicyRule

logger = logging.getLogger(__name__)


class RedisClient:
    """Async Redis client for caching and rate limiting."""
    
    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or get_settings()
        self._pool: Optional[ConnectionPool] = None
        self._client: Optional[redis.Redis] = None
    
    async def connect(self) -> None:
        """Establish connection to Redis."""
        try:
            self._pool = ConnectionPool.from_url(
                self.settings.redis_url,
                max_connections=50,
                decode_responses=True
            )
            self._client = redis.Redis(connection_pool=self._pool)
            # Test connection
            await self._client.ping()
            logger.info("Redis connection established successfully")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise
    
    async def disconnect(self) -> None:
        """Close Redis connection."""
        if self._client:
            await self._client.close()
        if self._pool:
            await self._pool.disconnect()
        logger.info("Redis connection closed")
    
    async def is_connected(self) -> bool:
        """Check if Redis is connected."""
        try:
            if self._client:
                await self._client.ping()
                return True
        except Exception:
            pass
        return False
    
    @property
    def client(self) -> redis.Redis:
        """Get Redis client instance."""
        if not self._client:
            raise RuntimeError("Redis client not connected")
        return self._client
    
    # ==================== Policy Management ====================
    
    async def store_policy(self, policy: PolicyRule) -> bool:
        """Store a policy rule in Redis."""
        try:
            key = f"{self.settings.redis_policy_prefix}{policy.rule_id}"
            await self.client.setex(
                key,
                self.settings.policy_cache_ttl,
                policy.model_dump_json()
            )
            # Add to policy index
            await self.client.sadd(
                f"{self.settings.redis_policy_prefix}index",
                policy.rule_id
            )
            logger.debug(f"Stored policy: {policy.rule_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to store policy {policy.rule_id}: {e}")
            return False
    
    async def get_policy(self, rule_id: str) -> Optional[PolicyRule]:
        """Retrieve a policy rule from Redis."""
        try:
            key = f"{self.settings.redis_policy_prefix}{rule_id}"
            data = await self.client.get(key)
            if data:
                return PolicyRule.model_validate_json(data)
            return None
        except Exception as e:
            logger.error(f"Failed to get policy {rule_id}: {e}")
            return None
    
    async def get_all_policies(self) -> List[PolicyRule]:
        """Retrieve all active policies from Redis."""
        policies = []
        try:
            # Get all policy IDs from index
            index_key = f"{self.settings.redis_policy_prefix}index"
            rule_ids = await self.client.smembers(index_key)
            
            if not rule_ids:
                return policies
            
            # Batch fetch all policies
            keys = [f"{self.settings.redis_policy_prefix}{rid}" for rid in rule_ids]
            values = await self.client.mget(keys)
            
            for value in values:
                if value:
                    try:
                        policy = PolicyRule.model_validate_json(value)
                        if policy.enabled:
                            policies.append(policy)
                    except Exception as e:
                        logger.warning(f"Failed to parse policy: {e}")
            
            # Sort by priority (lower = higher priority)
            policies.sort(key=lambda p: p.priority)
            logger.debug(f"Loaded {len(policies)} active policies")
            
        except Exception as e:
            logger.error(f"Failed to get all policies: {e}")
        
        return policies
    
    async def delete_policy(self, rule_id: str) -> bool:
        """Delete a policy rule from Redis."""
        try:
            key = f"{self.settings.redis_policy_prefix}{rule_id}"
            await self.client.delete(key)
            await self.client.srem(
                f"{self.settings.redis_policy_prefix}index",
                rule_id
            )
            logger.debug(f"Deleted policy: {rule_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete policy {rule_id}: {e}")
            return False
    
    async def refresh_policies(self, policies: List[PolicyRule]) -> int:
        """Refresh all policies in cache."""
        count = 0
        try:
            # Clear existing policies
            index_key = f"{self.settings.redis_policy_prefix}index"
            existing = await self.client.smembers(index_key)
            
            for rule_id in existing:
                await self.delete_policy(rule_id)
            
            # Store new policies
            for policy in policies:
                if await self.store_policy(policy):
                    count += 1
            
            logger.info(f"Refreshed {count} policies in cache")
        except Exception as e:
            logger.error(f"Failed to refresh policies: {e}")
        
        return count
    
    # ==================== Rate Limiting ====================
    
    async def check_rate_limit(self, agent_id: str) -> tuple[bool, int]:
        """
        Check if agent has exceeded rate limit.
        Returns (is_allowed, remaining_requests).
        """
        try:
            key = f"{self.settings.redis_rate_limit_prefix}{agent_id}"
            
            # Use Redis pipeline for atomic operations
            pipe = self.client.pipeline()
            pipe.incr(key)
            pipe.ttl(key)
            results = await pipe.execute()
            
            current_count = results[0]
            ttl = results[1]
            
            # Set expiry on first request
            if ttl == -1:
                await self.client.expire(key, self.settings.rate_limit_window_seconds)
            
            remaining = max(0, self.settings.rate_limit_requests - current_count)
            is_allowed = current_count <= self.settings.rate_limit_requests
            
            return is_allowed, remaining
            
        except Exception as e:
            logger.error(f"Rate limit check failed for {agent_id}: {e}")
            # Fail open on error
            return True, self.settings.rate_limit_requests
    
    async def get_rate_limit_info(self, agent_id: str) -> Dict[str, Any]:
        """Get rate limit information for an agent."""
        try:
            key = f"{self.settings.redis_rate_limit_prefix}{agent_id}"
            
            pipe = self.client.pipeline()
            pipe.get(key)
            pipe.ttl(key)
            results = await pipe.execute()
            
            current_count = int(results[0] or 0)
            ttl = max(0, results[1] or 0)
            
            return {
                "agent_id": agent_id,
                "current_requests": current_count,
                "limit": self.settings.rate_limit_requests,
                "remaining": max(0, self.settings.rate_limit_requests - current_count),
                "reset_in_seconds": ttl,
                "window_seconds": self.settings.rate_limit_window_seconds
            }
        except Exception as e:
            logger.error(f"Failed to get rate limit info for {agent_id}: {e}")
            return {}
    
    # ==================== Approval Tracking ====================
    
    async def store_pending_approval(
        self, 
        approval_id: str, 
        request_data: Dict[str, Any],
        ttl: int = 3600
    ) -> bool:
        """Store a pending approval request."""
        try:
            key = f"sentinel:approval:{approval_id}"
            await self.client.setex(key, ttl, json.dumps(request_data, default=str))
            return True
        except Exception as e:
            logger.error(f"Failed to store pending approval {approval_id}: {e}")
            return False
    
    async def get_pending_approval(self, approval_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a pending approval request."""
        try:
            key = f"sentinel:approval:{approval_id}"
            data = await self.client.get(key)
            if data:
                return json.loads(data)
            return None
        except Exception as e:
            logger.error(f"Failed to get pending approval {approval_id}: {e}")
            return None
    
    async def delete_pending_approval(self, approval_id: str) -> bool:
        """Delete a pending approval request."""
        try:
            key = f"sentinel:approval:{approval_id}"
            await self.client.delete(key)
            return True
        except Exception as e:
            logger.error(f"Failed to delete pending approval {approval_id}: {e}")
            return False
    
    # ==================== Metrics ====================
    
    async def increment_metric(self, metric_name: str, value: int = 1) -> None:
        """Increment a metric counter."""
        try:
            key = f"sentinel:metrics:{metric_name}"
            await self.client.incrby(key, value)
        except Exception as e:
            logger.error(f"Failed to increment metric {metric_name}: {e}")
    
    async def get_metric(self, metric_name: str) -> int:
        """Get a metric value."""
        try:
            key = f"sentinel:metrics:{metric_name}"
            value = await self.client.get(key)
            return int(value) if value else 0
        except Exception as e:
            logger.error(f"Failed to get metric {metric_name}: {e}")
            return 0
    
    async def record_latency(self, latency_ms: float) -> None:
        """Record request latency for percentile calculations."""
        try:
            key = "sentinel:metrics:latencies"
            # Keep last 10000 latencies
            await self.client.lpush(key, latency_ms)
            await self.client.ltrim(key, 0, 9999)
        except Exception as e:
            logger.error(f"Failed to record latency: {e}")
    
    async def get_latency_percentiles(self) -> Dict[str, float]:
        """Calculate latency percentiles."""
        try:
            key = "sentinel:metrics:latencies"
            latencies = await self.client.lrange(key, 0, -1)
            
            if not latencies:
                return {"p50": 0.0, "p95": 0.0, "p99": 0.0, "avg": 0.0}
            
            values = sorted([float(l) for l in latencies])
            n = len(values)
            
            return {
                "p50": values[int(n * 0.50)] if n > 0 else 0.0,
                "p95": values[int(n * 0.95)] if n > 0 else 0.0,
                "p99": values[int(n * 0.99)] if n > 0 else 0.0,
                "avg": sum(values) / n if n > 0 else 0.0
            }
        except Exception as e:
            logger.error(f"Failed to get latency percentiles: {e}")
            return {"p50": 0.0, "p95": 0.0, "p99": 0.0, "avg": 0.0}


# Global Redis client instance
redis_client = RedisClient()


async def get_redis() -> RedisClient:
    """Dependency injection for Redis client."""
    return redis_client
