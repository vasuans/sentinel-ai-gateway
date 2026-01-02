"""
Mock Approval Service
Simulates an external human-in-the-loop approval workflow.
For development and testing purposes.
"""
import asyncio
import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, BackgroundTasks, HTTPException
from pydantic import BaseModel, Field

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mock-approval")

app = FastAPI(
    title="Mock Approval Service",
    description="Simulates human-in-the-loop approval workflows for Sentinel Gateway",
    version="1.0.0",
)

# In-memory storage for pending approvals
pending_approvals: Dict[str, Dict[str, Any]] = {}
approval_history: List[Dict[str, Any]] = []


class ApprovalWebhookPayload(BaseModel):
    """Incoming webhook payload from Sentinel Gateway."""
    event: str
    approval_id: str
    request_id: str
    agent_id: str
    action_type: str
    target_resource: str
    risk_score: float
    risk_level: str
    matched_rules: List[str]
    parameters: Dict[str, Any] = Field(default_factory=dict)
    context: Dict[str, Any] = Field(default_factory=dict)
    requested_at: str
    expires_at: Optional[str] = None
    callback_url: str


class ApprovalDecision(BaseModel):
    """Approval decision from human reviewer."""
    approved: bool
    approver_id: str = "mock_approver"
    reason: Optional[str] = None


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "service": "Mock Approval Service",
        "status": "operational",
        "pending_approvals": len(pending_approvals),
    }


@app.get("/health")
async def health():
    """Health check."""
    return {"status": "healthy"}


@app.post("/webhook")
async def receive_approval_request(
    payload: ApprovalWebhookPayload,
    background_tasks: BackgroundTasks,
):
    """
    Receive approval request webhook from Sentinel Gateway.
    In a real system, this would:
    1. Store the request in a database
    2. Notify reviewers via Slack/Email/etc.
    3. Present a UI for review
    """
    logger.info(f"Received approval request: {payload.approval_id}")
    logger.info(f"  Agent: {payload.agent_id}")
    logger.info(f"  Action: {payload.action_type}")
    logger.info(f"  Risk Score: {payload.risk_score}")
    logger.info(f"  Matched Rules: {payload.matched_rules}")
    
    # Store pending approval
    pending_approvals[payload.approval_id] = {
        "payload": payload.model_dump(),
        "received_at": datetime.utcnow().isoformat(),
        "status": "pending",
    }
    
    # Simulate auto-approval after delay for testing
    # In production, this would wait for human decision
    if payload.risk_score < 0.9:
        background_tasks.add_task(
            auto_approve_after_delay,
            payload.approval_id,
            delay_seconds=5.0,
        )
    
    return {
        "status": "received",
        "approval_id": payload.approval_id,
        "message": "Approval request queued for review",
        "estimated_review_time": "5 seconds (auto-approval for testing)",
    }


async def auto_approve_after_delay(approval_id: str, delay_seconds: float):
    """Auto-approve after a delay for testing purposes."""
    await asyncio.sleep(delay_seconds)
    
    if approval_id in pending_approvals:
        approval = pending_approvals[approval_id]
        payload = approval["payload"]
        
        # Make callback to Sentinel Gateway
        import httpx
        
        try:
            callback_url = f"http://gateway:8000{payload['callback_url']}"
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    callback_url,
                    params={
                        "approved": True,
                        "approver_id": "auto_approver",
                        "reason": "Auto-approved for testing (risk_score < 0.9)",
                    },
                )
                logger.info(
                    f"Auto-approval callback sent for {approval_id}: "
                    f"status={response.status_code}"
                )
        except Exception as e:
            logger.error(f"Failed to send auto-approval callback: {e}")
        
        # Update status
        pending_approvals[approval_id]["status"] = "auto_approved"
        pending_approvals[approval_id]["decided_at"] = datetime.utcnow().isoformat()
        
        # Move to history
        approval_history.append(pending_approvals.pop(approval_id))


@app.get("/approvals")
async def list_pending_approvals():
    """List all pending approvals."""
    return {
        "pending": list(pending_approvals.values()),
        "count": len(pending_approvals),
    }


@app.get("/approvals/{approval_id}")
async def get_approval(approval_id: str):
    """Get a specific approval by ID."""
    if approval_id in pending_approvals:
        return pending_approvals[approval_id]
    
    # Check history
    for item in approval_history:
        if item["payload"]["approval_id"] == approval_id:
            return item
    
    raise HTTPException(status_code=404, detail="Approval not found")


@app.post("/approvals/{approval_id}/decide")
async def submit_decision(approval_id: str, decision: ApprovalDecision):
    """
    Submit a manual approval/denial decision.
    Used for testing the human-in-the-loop flow.
    """
    if approval_id not in pending_approvals:
        raise HTTPException(status_code=404, detail="Approval not found or already decided")
    
    approval = pending_approvals[approval_id]
    payload = approval["payload"]
    
    # Make callback to Sentinel Gateway
    import httpx
    
    try:
        callback_url = f"http://gateway:8000{payload['callback_url']}"
        async with httpx.AsyncClient() as client:
            response = await client.post(
                callback_url,
                params={
                    "approved": decision.approved,
                    "approver_id": decision.approver_id,
                    "reason": decision.reason or "",
                },
            )
            logger.info(
                f"Decision callback sent for {approval_id}: "
                f"approved={decision.approved}, status={response.status_code}"
            )
    except Exception as e:
        logger.error(f"Failed to send decision callback: {e}")
        raise HTTPException(status_code=500, detail=f"Callback failed: {e}")
    
    # Update status
    status = "approved" if decision.approved else "denied"
    pending_approvals[approval_id]["status"] = status
    pending_approvals[approval_id]["decided_at"] = datetime.utcnow().isoformat()
    pending_approvals[approval_id]["decision"] = decision.model_dump()
    
    # Move to history
    approval_history.append(pending_approvals.pop(approval_id))
    
    return {
        "status": status,
        "approval_id": approval_id,
        "message": f"Approval {status} successfully",
    }


@app.get("/history")
async def get_approval_history(limit: int = 100):
    """Get approval decision history."""
    return {
        "history": approval_history[-limit:],
        "total": len(approval_history),
    }


@app.delete("/approvals")
async def clear_all():
    """Clear all pending approvals and history (for testing)."""
    pending_approvals.clear()
    approval_history.clear()
    return {"status": "cleared"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
