# Sentinel: Enterprise AI Governance Gateway

A production-ready, scalable middleware platform that governs multiple concurrent AI Agents. Acts as a "Zero-Trust" proxy between Agents and their tools (Databases, APIs, SaaS).

## 🏗️ Architecture

```
                                    ┌─────────────────────────────────────────────────────────┐
                                    │                    SENTINEL GATEWAY                      │
┌──────────┐                        │  ┌─────────────┐  ┌──────────────┐  ┌───────────────┐   │
│ AI Agent │──── API Key Auth ────▶│  │ Rate Limit  │─▶│Policy Engine │─▶│Circuit Breaker│   │
│   #1     │                        │  │  Middleware │  │  + PII Scrub │  │Shadow/Enforce │   │
└──────────┘                        │  └─────────────┘  └──────────────┘  └───────┬───────┘   │
                                    │                                              │           │
┌──────────┐                        │                                              ▼           │
│ AI Agent │──── Bearer Token ────▶│                                    ┌───────────────┐     │
│   #2     │                        │                                    │ Allow/Deny/   │     │
└──────────┘                        │                                    │ Pending       │     │
                                    │                                    └───────┬───────┘     │
┌──────────┐                        │                                            │             │
│ AI Agent │──── agent_sk_... ────▶│                                            ▼             │
│   #N     │                        │                                    ┌───────────────┐     │
└──────────┘                        │                                    │  Audit Log    │     │
                                    │                                    │  (Postgres)   │     │
                                    │                                    └───────────────┘     │
                                    └─────────────────────────────────────────────────────────┘
                                                         │
                                         ┌───────────────┼───────────────┐
                                         ▼               ▼               ▼
                                    ┌─────────┐   ┌───────────┐   ┌───────────┐
                                    │  Redis  │   │PostgreSQL │   │ Approval  │
                                    │ (Cache) │   │  (Audit)  │   │ Webhook   │
                                    └─────────┘   └───────────┘   └───────────┘
```

## ✨ Features

### 🔐 Zero-Trust Authentication
- API Key validation with `agent_sk_` prefix
- Per-agent permissions and rate limits
- Structured request/response logging

### 🧠 Dynamic Policy Engine
- Real-time policy updates via Redis (no restart needed)
- Configurable rules: amount limits, protected resources, bulk operations
- Priority-based policy evaluation

### 🔒 PII Sanitization
- Microsoft Presidio integration for enterprise-grade PII detection
- Automatic masking of SSN, emails, credit cards, phone numbers
- Sanitized data in all logs and audit trails

### ⚡ Circuit Breaker
- **Shadow Mode**: Log but don't block (safe enterprise onboarding)
- **Enforce Mode**: Block unsafe actions
- Runtime mode switching without restart

### 👥 Human-in-the-Loop
- Automatic approval requests for high-risk actions (0.8 < risk_score < 1.0)
- Webhook integration with external approval services
- 202 Pending responses with approval tracking

### 📊 Observability
- Prometheus metrics endpoint (`/metrics`)
- JSON structured logging (Datadog/Splunk compatible)
- Comprehensive audit trail in PostgreSQL

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose
- 4GB+ RAM available

### Start the Stack

```bash
# Clone and navigate
cd sentinel-gateway

# Start all services
docker-compose up -d

# View logs
docker-compose logs -f gateway

# Check health
curl http://localhost:8000/health
```

### Start with Monitoring (Prometheus + Grafana)

```bash
docker-compose --profile monitoring up -d

# Access:
# - Gateway: http://localhost:8000
# - Prometheus: http://localhost:9090
# - Grafana: http://localhost:3000 (admin/sentinel)
```

## 📡 API Usage

### Authentication

All API requests (except health endpoints) require an API key:

```bash
Authorization: Bearer agent_sk_test_key_12345678901234567890
```

### Evaluate a Request

```bash
curl -X POST http://localhost:8000/api/v1/gateway/evaluate \
  -H "Authorization: Bearer agent_sk_test_key_12345678901234567890" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "trading_bot_01",
    "action_type": "refund",
    "target_resource": "payments/refund",
    "parameters": {
      "amount": 750,
      "customer_email": "john@example.com",
      "reason": "Product defective"
    },
    "context": {
      "user_id": "user_123",
      "session_id": "sess_abc"
    }
  }'
```

**Response (Denied - exceeds $500 limit):**
```json
{
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "denied",
  "decision": "deny",
  "message": "Request denied: Amount $750 exceeds limit of $500 (Refund Amount Limit)",
  "risk_level": "high",
  "approval_required": false,
  "forwarded": false
}
```

### Manage Policies

```bash
# List all policies
curl http://localhost:8000/api/v1/policies \
  -H "Authorization: Bearer agent_sk_test_key_12345678901234567890"

# Create a new policy
curl -X POST http://localhost:8000/api/v1/policies \
  -H "Authorization: Bearer agent_sk_test_key_12345678901234567890" \
  -H "Content-Type: application/json" \
  -d '{
    "rule_id": "no_weekend_payments",
    "name": "Block Weekend Payments",
    "description": "Block all payments during weekends",
    "action_types": ["payment"],
    "conditions": {"blocked_days": ["saturday", "sunday"]},
    "risk_score_modifier": 1.0,
    "enabled": true,
    "priority": 5
  }'
```

### Switch Gateway Mode

```bash
# Get current mode
curl http://localhost:8000/api/v1/gateway/mode \
  -H "Authorization: Bearer agent_sk_test_key_12345678901234567890"

# Switch to shadow mode (for safe testing)
curl -X PUT "http://localhost:8000/api/v1/gateway/mode?mode=SHADOW" \
  -H "Authorization: Bearer agent_sk_test_key_12345678901234567890"
```

## 📋 Default Policies

| Rule ID | Name | Description | Risk Modifier |
|---------|------|-------------|---------------|
| `refund_limit_500` | Refund Amount Limit | Block refunds > $500 | 0.4 |
| `payment_limit_10000` | Payment Amount Limit | Approval needed for payments > $10,000 | 0.3 |
| `admin_action_high_risk` | Admin Actions High Risk | All admin actions flagged | 0.6 |
| `user_data_access` | User Data Access Control | Requires justification | 0.3 |
| `database_write_protection` | Database Write Protection | Protected tables: users, payments, credentials | 0.5 |
| `bulk_operation_limit` | Bulk Operation Limit | Max 1000 affected rows | 0.35 |

## 🔧 Configuration

Environment variables (set in `docker-compose.yml` or `.env`):

| Variable | Default | Description |
|----------|---------|-------------|
| `SENTINEL_GATEWAY_MODE` | `ENFORCE` | `SHADOW` or `ENFORCE` |
| `SENTINEL_REDIS_HOST` | `localhost` | Redis hostname |
| `SENTINEL_POSTGRES_HOST` | `localhost` | PostgreSQL hostname |
| `SENTINEL_RISK_SCORE_APPROVAL_THRESHOLD` | `0.8` | Risk score requiring approval |
| `SENTINEL_RISK_SCORE_BLOCK_THRESHOLD` | `1.0` | Risk score for automatic block |
| `SENTINEL_RATE_LIMIT_REQUESTS` | `1000` | Max requests per window |
| `SENTINEL_RATE_LIMIT_WINDOW_SECONDS` | `60` | Rate limit window |
| `SENTINEL_APPROVAL_WEBHOOK_URL` | - | External approval service URL |

## 📊 Metrics

Available at `GET /metrics` (Prometheus format):

| Metric | Type | Description |
|--------|------|-------------|
| `sentinel_requests_total` | Counter | Total requests by agent, action, decision |
| `sentinel_blocked_requests_total` | Counter | Blocked requests |
| `sentinel_request_latency_seconds` | Histogram | Request latency (p50, p95, p99) |
| `sentinel_risk_score` | Histogram | Risk score distribution |
| `sentinel_pii_detections_total` | Counter | PII detections by type |
| `sentinel_active_policies` | Gauge | Number of active policies |
| `sentinel_pending_approvals` | Gauge | Current pending approvals |

## 🧪 Testing

```bash
# Run tests
docker-compose exec gateway pytest tests/ -v

# Test with coverage
docker-compose exec gateway pytest tests/ --cov=app --cov-report=html
```

### Test Scenarios

1. **Allow**: Request within all policy limits
2. **Deny**: Refund > $500
3. **Pending Approval**: Payment between $10,000-$50,000
4. **Shadow Mode**: Same requests, logged but not blocked
5. **PII Detection**: Request with SSN/email, check sanitized logs

## 📁 Project Structure

```
sentinel-gateway/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI application
│   ├── config.py            # Configuration management
│   ├── middleware.py        # Auth, logging, rate limiting
│   ├── policy_engine.py     # Dynamic policy evaluation
│   ├── circuit_breaker.py   # Shadow/enforce modes
│   ├── database.py          # PostgreSQL audit logging
│   ├── redis_client.py      # Redis caching
│   ├── metrics.py           # Prometheus metrics
│   └── models.py            # Pydantic models
├── scripts/
│   ├── init-db.sql          # Database initialization
│   ├── mock_approval_service.py
│   └── prometheus.yml
├── tests/
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── README.md
```

## 🔐 Security Considerations

- All PII is sanitized before logging
- API keys should be rotated regularly
- Use secrets management in production (Vault, AWS Secrets Manager)
- Enable TLS in production (via reverse proxy)
- Audit logs are tamper-evident (use append-only tables)

## 📄 License

MIT License - See LICENSE file for details.
