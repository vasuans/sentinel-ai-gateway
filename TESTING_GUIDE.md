# Sentinel AI Gateway - Testing Guide

## Prerequisites

### Option A: Docker Desktop
1. Install Docker Desktop from https://www.docker.com/products/docker-desktop/
2. Start Docker Desktop and wait for "Docker Desktop is running"
3. Verify installation:
   ```bash
   docker --version
   docker-compose --version
   ```

### Option B: Podman
1. Install Podman from https://podman.io/getting-started/installation
2. Install podman-compose:
   ```bash
   pip install podman-compose
   ```
3. Verify installation:
   ```bash
   podman --version
   podman-compose --version
   ```

---

## Quick Start (5 minutes)

### Step 1: Navigate
```bash
cd sentinel-ai-gateway
```

### Step 2: Start the Stack

**Docker Desktop:**
```bash
docker-compose up -d
```

**Podman:**
```bash
podman-compose up -d
```

### Step 3: Wait for Services (about 30-60 seconds)
```bash
# Check all containers are running
docker-compose ps   # or: podman-compose ps

# Expected output - all should show "Up" or "running":
# sentinel-gateway    Up (healthy)
# sentinel-redis      Up (healthy)
# sentinel-postgres   Up (healthy)
# sentinel-approval   Up (healthy)
```

### Step 4: Verify Health
```bash
curl http://localhost:8000/health
```

Expected response:
```json
{
  "status": "healthy",
  "gateway_mode": "SHADOW",
  "components": {
    "redis": "connected",
    "database": "connected"
  }
}
```

---

## Test Scenarios

### Test 1: Basic Request (Should be ALLOWED)
A simple refund under $500 limit:
```bash
curl -X POST http://localhost:8000/api/v1/gateway/evaluate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer agent_sk_test_key_12345678901234567890" \
  -d '{
    "agent_id": "support-bot",
    "action_type": "refund",
    "target_resource": "payments/refund",
    "parameters": {"amount": 100, "customer_id": "cust_123"}
  }'
```

Expected: `"decision": "allow"`, `"risk_level": "medium"`

---

### Test 2: High-Value Refund (Should be DENIED)
Refund over $500 limit:
```bash
curl -X POST http://localhost:8000/api/v1/gateway/evaluate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer agent_sk_test_key_12345678901234567890" \
  -d '{
    "agent_id": "support-bot",
    "action_type": "refund",
    "target_resource": "payments/refund",
    "parameters": {"amount": 750}
  }'
```

Expected: `"decision": "deny"`, message mentions exceeding $500 limit

---

### Test 3: PII Sanitization
Request with sensitive data (SSN, email):
```bash
curl -X POST http://localhost:8000/api/v1/gateway/evaluate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer agent_sk_test_key_12345678901234567890" \
  -d '{
    "agent_id": "data-bot",
    "action_type": "query",
    "target_resource": "users/lookup",
    "parameters": {
      "ssn": "123-45-6789",
      "email": "john@example.com",
      "credit_card": "4111-1111-1111-1111"
    }
  }'
```

Check logs to verify PII is masked:
```bash
docker-compose logs gateway | grep "sanitized"
```

---

### Test 4: Admin Action (HIGH RISK)
```bash
curl -X POST http://localhost:8000/api/v1/gateway/evaluate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer agent_sk_test_key_12345678901234567890" \
  -d '{
    "agent_id": "admin-bot",
    "action_type": "admin",
    "target_resource": "system/config",
    "parameters": {"setting": "debug_mode", "value": true}
  }'
```

Expected: `"risk_level": "high"` due to admin action policy

---

### Test 5: Database Write to Protected Table
```bash
curl -X POST http://localhost:8000/api/v1/gateway/evaluate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer agent_sk_test_key_12345678901234567890" \
  -d '{
    "agent_id": "db-bot",
    "action_type": "database_write",
    "target_resource": "database/users",
    "parameters": {"table": "users", "operation": "update"}
  }'
```

Expected: Denied - "users" is a protected table

---

### Test 6: Switch Between Shadow and Enforce Mode

**Check current mode:**
```bash
curl http://localhost:8000/api/v1/gateway/mode \
  -H "Authorization: Bearer agent_sk_test_key_12345678901234567890"
```

**Switch to ENFORCE mode:**
```bash
curl -X PUT "http://localhost:8000/api/v1/gateway/mode?mode=ENFORCE" \
  -H "Authorization: Bearer agent_sk_test_key_12345678901234567890"
```

**Switch back to SHADOW mode:**
```bash
curl -X PUT "http://localhost:8000/api/v1/gateway/mode?mode=SHADOW" \
  -H "Authorization: Bearer agent_sk_test_key_12345678901234567890"
```

In SHADOW mode, violations are logged but requests return 200.
In ENFORCE mode, violations are blocked (403) or require approval (202).

---

### Test 7: View Policies
```bash
curl http://localhost:8000/api/v1/policies \
  -H "Authorization: Bearer agent_sk_test_key_12345678901234567890"
```

---

### Test 8: Check Metrics
```bash
curl http://localhost:8000/metrics
```

Look for:
- `sentinel_requests_total` - request counts
- `sentinel_request_duration_seconds` - latency
- `sentinel_risk_score` - risk score distribution

---

### Test 9: View Audit Logs
```bash
curl "http://localhost:8000/api/v1/audit/logs?limit=10" \
  -H "Authorization: Bearer agent_sk_test_key_12345678901234567890"
```

---

### Test 10: Rate Limiting
Run this in a loop to trigger rate limiting:
```bash
for i in {1..20}; do
  curl -s -o /dev/null -w "%{http_code}\n" \
    http://localhost:8000/api/v1/gateway/evaluate \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer agent_sk_test_key_12345678901234567890" \
    -d '{"agent_id":"test","action_type":"query","target_resource":"test"}'
done
```

(Default limit is 1000/minute, so you'd need more requests to hit it)

---

## Monitoring (Optional)

Start with Prometheus and Grafana:
```bash
docker-compose --profile monitoring up -d
```

Access:
- **Prometheus**: http://localhost:9090
- **Grafana**: http://localhost:3000 (admin/sentinel)

---

## Viewing Logs

**All services:**
```bash
docker-compose logs -f
```

**Gateway only:**
```bash
docker-compose logs -f gateway
```

**Filter for specific events:**
```bash
docker-compose logs gateway | grep "decision"
docker-compose logs gateway | grep "denied"
docker-compose logs gateway | grep "pii"
```

---

## Stopping the Stack

```bash
docker-compose down
```

**To also remove volumes (database data):**
```bash
docker-compose down -v
```

---

## Troubleshooting

### Container won't start
```bash
# Check logs
docker-compose logs gateway

# Rebuild if needed
docker-compose build --no-cache gateway
docker-compose up -d
```

### Port already in use
```bash
# Check what's using port 8000
lsof -i :8000   # Mac/Linux
netstat -ano | findstr :8000   # Windows

# Use different port in docker-compose.yml:
# ports:
#   - "8080:8000"
```

### Redis/Postgres connection errors
```bash
# Ensure services are healthy
docker-compose ps

# Restart specific service
docker-compose restart redis
docker-compose restart postgres
```

### Podman-specific issues
```bash
# If networking issues, try:
podman-compose down
podman network prune
podman-compose up -d
```

---

## Windows PowerShell Commands

If using PowerShell instead of bash:
```powershell
# Start
docker-compose up -d

# Test health
Invoke-RestMethod -Uri "http://localhost:8000/health"

# Test evaluation
$body = @{
    agent_id = "support-bot"
    action_type = "refund"
    target_resource = "payments/refund"
    parameters = @{amount = 100}
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:8000/api/v1/gateway/evaluate" `
    -Method Post `
    -Headers @{
        "Content-Type" = "application/json"
        "Authorization" = "Bearer agent_sk_test_key_12345678901234567890"
    } `
    -Body $body
```

---

## Quick Reference - API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/metrics` | GET | Prometheus metrics |
| `/api/v1/gateway/evaluate` | POST | Evaluate agent request |
| `/api/v1/gateway/mode` | GET/PUT | Get/set gateway mode |
| `/api/v1/policies` | GET/POST | List/create policies |
| `/api/v1/policies/{id}` | GET/DELETE | Get/delete policy |
| `/api/v1/audit/logs` | GET | Query audit logs |
| `/api/v1/audit/stats` | GET | Aggregate statistics |

---

## Test API Keys

Use these pre-configured test keys:
- `agent_sk_test_key_12345678901234567890` - Full access
- `agent_sk_demo_key_abcdefghijklmnopqrst` - Demo access
