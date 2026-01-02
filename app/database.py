"""
Sentinel Gateway Database Module.
Handles PostgreSQL connections and audit log persistence.
"""
import logging
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, AsyncGenerator, Dict, List, Optional
from uuid import UUID

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    Index,
    Integer,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, UUID as PG_UUID
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import NullPool

from app.config import Settings, get_settings
from app.models import AuditLogEntry, DecisionType, RiskLevel

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    """SQLAlchemy declarative base."""
    pass


class AuditLog(Base):
    """Audit log table for persistent storage."""
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    log_id = Column(PG_UUID(as_uuid=True), unique=True, nullable=False, index=True)
    request_id = Column(PG_UUID(as_uuid=True), nullable=False, index=True)
    agent_id = Column(String(128), nullable=False, index=True)
    action_type = Column(String(64), nullable=False, index=True)
    target_resource = Column(String(512), nullable=False)
    decision = Column(String(32), nullable=False, index=True)
    risk_score = Column(Float, nullable=False)
    risk_level = Column(String(16), nullable=False, index=True)
    matched_rules = Column(ARRAY(String), default=[])
    pii_detected = Column(Boolean, default=False, index=True)
    pii_fields = Column(ARRAY(String), default=[])
    gateway_mode = Column(String(16), nullable=False)
    sanitized_request = Column(JSON, default={})
    response_status = Column(String(32), nullable=False)
    processing_time_ms = Column(Float, nullable=False)
    client_ip = Column(String(45), nullable=True)
    user_agent = Column(String(512), nullable=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    
    # Composite indexes for common queries
    __table_args__ = (
        Index('ix_audit_agent_timestamp', 'agent_id', 'timestamp'),
        Index('ix_audit_decision_timestamp', 'decision', 'timestamp'),
        Index('ix_audit_risk_level_timestamp', 'risk_level', 'timestamp'),
    )


class PolicyAudit(Base):
    """Policy change audit table."""
    __tablename__ = "policy_audits"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    policy_id = Column(String(128), nullable=False, index=True)
    action = Column(String(32), nullable=False)  # created, updated, deleted
    old_value = Column(JSON, nullable=True)
    new_value = Column(JSON, nullable=True)
    changed_by = Column(String(128), nullable=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)


class ApprovalAudit(Base):
    """Approval decision audit table."""
    __tablename__ = "approval_audits"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    approval_id = Column(PG_UUID(as_uuid=True), unique=True, nullable=False, index=True)
    request_id = Column(PG_UUID(as_uuid=True), nullable=False, index=True)
    agent_id = Column(String(128), nullable=False, index=True)
    action_type = Column(String(64), nullable=False)
    risk_score = Column(Float, nullable=False)
    status = Column(String(32), nullable=False, index=True)
    approver_id = Column(String(128), nullable=True)
    reason = Column(Text, nullable=True)
    requested_at = Column(DateTime, nullable=False)
    decided_at = Column(DateTime, nullable=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow)


class Database:
    """Async database manager for PostgreSQL."""
    
    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or get_settings()
        self._engine = None
        self._session_factory = None
    
    async def connect(self) -> None:
        """Initialize database connection and create tables."""
        try:
            self._engine = create_async_engine(
                self.settings.postgres_url,
                pool_size=self.settings.postgres_pool_size,
                max_overflow=self.settings.postgres_max_overflow,
                pool_pre_ping=True,
                echo=self.settings.debug,
            )
            
            self._session_factory = async_sessionmaker(
                bind=self._engine,
                class_=AsyncSession,
                expire_on_commit=False,
                autoflush=False,
            )
            
            # Create tables
            async with self._engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            
            logger.info("PostgreSQL connection established and tables created")
            
        except Exception as e:
            logger.error(f"Failed to connect to PostgreSQL: {e}")
            raise
    
    async def disconnect(self) -> None:
        """Close database connection."""
        if self._engine:
            await self._engine.dispose()
        logger.info("PostgreSQL connection closed")
    
    async def is_connected(self) -> bool:
        """Check if database is connected."""
        try:
            if self._engine:
                async with self._engine.connect() as conn:
                    await conn.execute(text("SELECT 1"))
                return True
        except Exception:
            pass
        return False
    
    @asynccontextmanager
    async def session(self) -> AsyncGenerator[AsyncSession, None]:
        """Get a database session."""
        if not self._session_factory:
            raise RuntimeError("Database not connected")
        
        session = self._session_factory()
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
    
    async def log_audit(self, entry: AuditLogEntry) -> bool:
        """Write an audit log entry to the database."""
        try:
            async with self.session() as session:
                audit_log = AuditLog(
                    log_id=entry.log_id,
                    request_id=entry.request_id,
                    agent_id=entry.agent_id,
                    action_type=entry.action_type.value,
                    target_resource=entry.target_resource,
                    decision=entry.decision.value,
                    risk_score=entry.risk_score,
                    risk_level=entry.risk_level.value,
                    matched_rules=entry.matched_rules,
                    pii_detected=entry.pii_detected,
                    pii_fields=entry.pii_fields,
                    gateway_mode=entry.gateway_mode,
                    sanitized_request=entry.sanitized_request,
                    response_status=entry.response_status,
                    processing_time_ms=entry.processing_time_ms,
                    client_ip=entry.client_ip,
                    user_agent=entry.user_agent,
                    timestamp=entry.timestamp,
                )
                session.add(audit_log)
                await session.commit()
                logger.debug(f"Audit log written: {entry.log_id}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")
            return False
    
    async def get_audit_logs(
        self,
        agent_id: Optional[str] = None,
        action_type: Optional[str] = None,
        decision: Optional[str] = None,
        risk_level: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Query audit logs with filters."""
        try:
            async with self.session() as session:
                query = session.query(AuditLog)
                
                if agent_id:
                    query = query.filter(AuditLog.agent_id == agent_id)
                if action_type:
                    query = query.filter(AuditLog.action_type == action_type)
                if decision:
                    query = query.filter(AuditLog.decision == decision)
                if risk_level:
                    query = query.filter(AuditLog.risk_level == risk_level)
                if start_time:
                    query = query.filter(AuditLog.timestamp >= start_time)
                if end_time:
                    query = query.filter(AuditLog.timestamp <= end_time)
                
                query = query.order_by(AuditLog.timestamp.desc())
                query = query.limit(limit).offset(offset)
                
                results = await session.execute(query)
                logs = results.scalars().all()
                
                return [
                    {
                        "log_id": str(log.log_id),
                        "request_id": str(log.request_id),
                        "agent_id": log.agent_id,
                        "action_type": log.action_type,
                        "target_resource": log.target_resource,
                        "decision": log.decision,
                        "risk_score": log.risk_score,
                        "risk_level": log.risk_level,
                        "matched_rules": log.matched_rules,
                        "pii_detected": log.pii_detected,
                        "gateway_mode": log.gateway_mode,
                        "processing_time_ms": log.processing_time_ms,
                        "timestamp": log.timestamp.isoformat(),
                    }
                    for log in logs
                ]
                
        except Exception as e:
            logger.error(f"Failed to query audit logs: {e}")
            return []
    
    async def get_audit_stats(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """Get aggregate statistics from audit logs."""
        try:
            async with self.session() as session:
                # Base time filter
                time_filter = ""
                if start_time:
                    time_filter += f" AND timestamp >= '{start_time.isoformat()}'"
                if end_time:
                    time_filter += f" AND timestamp <= '{end_time.isoformat()}'"
                
                # Total counts by decision
                result = await session.execute(text(f"""
                    SELECT 
                        decision,
                        COUNT(*) as count,
                        AVG(processing_time_ms) as avg_latency,
                        AVG(risk_score) as avg_risk
                    FROM audit_logs
                    WHERE 1=1 {time_filter}
                    GROUP BY decision
                """))
                
                stats = {
                    "total_requests": 0,
                    "by_decision": {},
                    "avg_latency_ms": 0.0,
                    "avg_risk_score": 0.0,
                }
                
                rows = result.fetchall()
                total_latency = 0.0
                total_risk = 0.0
                
                for row in rows:
                    decision, count, avg_lat, avg_risk = row
                    stats["by_decision"][decision] = {
                        "count": count,
                        "avg_latency_ms": float(avg_lat or 0),
                        "avg_risk_score": float(avg_risk or 0),
                    }
                    stats["total_requests"] += count
                    total_latency += (avg_lat or 0) * count
                    total_risk += (avg_risk or 0) * count
                
                if stats["total_requests"] > 0:
                    stats["avg_latency_ms"] = total_latency / stats["total_requests"]
                    stats["avg_risk_score"] = total_risk / stats["total_requests"]
                
                return stats
                
        except Exception as e:
            logger.error(f"Failed to get audit stats: {e}")
            return {}
    
    async def log_policy_change(
        self,
        policy_id: str,
        action: str,
        old_value: Optional[Dict] = None,
        new_value: Optional[Dict] = None,
        changed_by: Optional[str] = None,
    ) -> bool:
        """Log a policy change for auditing."""
        try:
            async with self.session() as session:
                audit = PolicyAudit(
                    policy_id=policy_id,
                    action=action,
                    old_value=old_value,
                    new_value=new_value,
                    changed_by=changed_by,
                )
                session.add(audit)
                await session.commit()
                return True
        except Exception as e:
            logger.error(f"Failed to log policy change: {e}")
            return False
    
    async def log_approval(
        self,
        approval_id: UUID,
        request_id: UUID,
        agent_id: str,
        action_type: str,
        risk_score: float,
        status: str,
        approver_id: Optional[str] = None,
        reason: Optional[str] = None,
        requested_at: Optional[datetime] = None,
        decided_at: Optional[datetime] = None,
    ) -> bool:
        """Log an approval decision."""
        try:
            async with self.session() as session:
                audit = ApprovalAudit(
                    approval_id=approval_id,
                    request_id=request_id,
                    agent_id=agent_id,
                    action_type=action_type,
                    risk_score=risk_score,
                    status=status,
                    approver_id=approver_id,
                    reason=reason,
                    requested_at=requested_at or datetime.utcnow(),
                    decided_at=decided_at,
                )
                session.add(audit)
                await session.commit()
                return True
        except Exception as e:
            logger.error(f"Failed to log approval: {e}")
            return False


# Global database instance
database = Database()


async def get_database() -> Database:
    """Dependency injection for database."""
    return database
