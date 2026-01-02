# Sentinel: Enterprise AI Governance Gateway

A production-ready middleware platform that governs AI agent actions in enterprise environments. Acts as a zero-trust proxy between AI agents and backend systems, ensuring every agent action is authenticated, evaluated against policies, sanitized for PII, and audited.

---

## The Problem

A single company might run dozens of AI agents: one answering customer questions, another processing returns, another syncing data between CRM and ERP systems, and others monitoring infrastructure or generating reports. These agents operate 24/7, executing thousands of actions per hour with minimal human oversight.
This shift from human-executed tasks to agent-executed tasks introduces critical challenges:

### 🚨 Uncontrolled Agent Actions
AI agents can perform thousands of actions per minute across multiple systems. Without governance:
- A misconfigured agent could issue unlimited refunds
- An agent might expose sensitive customer data in logs
- Bulk operations could corrupt production databases
- No audit trail exists for compliance or debugging

### 🔓 Security Gaps
Traditional API security wasn't designed for autonomous AI agents:
- Agents may have broad permissions but should be constrained contextually
- PII flows through agent requests and ends up in logs, analytics, and third-party services
- No mechanism to require human approval for high-risk actions
- Shadow IT: teams deploy agents without security review

### 📊 Compliance & Audit Requirements
Regulations (SOC2, GDPR, HIPAA, PCI-DSS) require:
- Complete audit trails of who did what, when
- Data minimization and PII protection
- Ability to demonstrate control over automated systems
- Evidence that sensitive actions require human oversight

### 🔧 Operational Challenges
- Deploying governance requires code changes in every agent
- Policy updates require redeployments
- No visibility into what agents are actually doing
- Incident response is slow without centralized logging

---

## The Solution

**Sentinel** is a governance gateway that sits between your AI agents and backend systems. Every agent request passes through Sentinel, which:

1. **Authenticates** the agent (zero-trust, every request verified)
2. **Evaluates** the request against dynamic policies
3. **Sanitizes** PII before logging or forwarding
4. **Decides** to allow, deny, or escalate for human approval
5. **Audits** everything with full context for compliance

### Key Benefits

| Challenge | Sentinel Solution |
|-----------|-------------------|
| Uncontrolled actions | Policy engine with amount limits, rate limits, resource protection |
| PII exposure | Microsoft Presidio integration masks SSN, emails, credit cards before logging |
| No human oversight | Automatic escalation to approval workflows for high-risk actions |
| Compliance gaps | Immutable audit log with request context, decisions, and timestamps |
| Slow policy updates | Redis-cached policies update in real-time, no restart needed |
| Risky deployments | Shadow mode lets you observe before enforcing |

---

## Architecture

### Request Flow

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                                    SENTINEL GATEWAY                                      │
│                                                                                          │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌───────────────────────┐  │
│  │    Auth      │    │   Policy     │    │     PII      │    │    Circuit Breaker    │  │
│  │  Middleware  │───▶│   Engine     │───▶│  Sanitizer   │───▶│    Decision Engine    │  │
│  │              │    │              │    │  (Presidio)  │    │                       │  │
│  └──────────────┘    └──────────────┘    └──────────────┘    └───────────┬───────────┘  │
│         │                   │                   │                        │              │
│         │                   ▼                   ▼                        │              │
│         │            ┌─────────────┐    ┌─────────────┐                  │              │
│         │            │   Redis     │    │  Sanitized  │                  │              │
│         │            │  (Policies) │    │   Request   │                  │              │
│         │            └─────────────┘    └─────────────┘                  │              │
│         │                                                                │              │
│         ▼                                                                ▼              │
│  ┌─────────────┐                                              ┌───────────────────┐     │
│  │ Rate Limit  │                                              │     DECISION      │     │
│  │   Check     │                                              │  ┌─────┬─────┬───┐│     │
│  └─────────────┘                                              │  │ALLOW│DENY │202││     │
│                                                               │  └──┬──┴──┬──┴─┬─┘│     │
│                                                               └─────┼─────┼────┼──┘     │
└─────────────────────────────────────────────────────────────────────┼─────┼────┼────────┘
                                                                      │     │    │
                         ┌────────────────────────────────────────────┘     │    │
                         │                                                  │    │
                         ▼                                                  ▼    ▼
              ┌─────────────────────┐                          ┌─────────────────────────┐
              │   FORWARD REQUEST   │                          │   RETURN TO AGENT       │
              │   to Target System  │                          │                         │
              │                     │                          │  • DENY: 403 + reason   │
              │  • Database         │                          │  • PENDING: 202 +       │
              │  • Payment API      │                          │    approval_id          │
              │  • SaaS Platform    │                          │                         │
              │  • Internal Service │                          │  Agent can:             │
              │                     │                          │  • Retry with changes   │
              └──────────┬──────────┘                          │  • Wait for approval    │
                         │                                     │  • Inform user          │
                         ▼                                     └─────────────────────────┘
              ┌─────────────────────┐
              │   Target System     │
              │   Processes Action  │
              │                     │
              │   Response flows    │
              │   back to Agent     │
              └─────────────────────┘
```

### Decision Flow Detail

```
                              ┌─────────────────┐
                              │ Evaluate Request│
                              │ Against Policies│
                              └────────┬────────┘
                                       │
                                       ▼
                              ┌─────────────────┐
                              │ Calculate Risk  │
                              │     Score       │
                              │   (0.0 - 1.0)   │
                              └────────┬────────┘
                                       │
                    ┌──────────────────┼──────────────────┐
                    │                  │                  │
                    ▼                  ▼                  ▼
            ┌───────────────┐  ┌───────────────┐  ┌───────────────┐
            │  risk < 0.8   │  │ 0.8 ≤ risk <1 │  │  risk ≥ 1.0   │
            │               │  │               │  │               │
            │    ALLOW      │  │PENDING_APPROVAL│ │     DENY      │
            └───────┬───────┘  └───────┬───────┘  └───────┬───────┘
                    │                  │                  │
                    ▼                  ▼                  ▼
            ┌───────────────┐  ┌───────────────┐  ┌───────────────┐
            │ Forward to    │  │ Send webhook  │  │ Return 403    │
            │ target system │  │ to approval   │  │ with denial   │
            │               │  │ service       │  │ reason        │
            │ Return result │  │               │  │               │
            │ to agent      │  │ Return 202    │  │ Log violation │
            └───────────────┘  │ + approval_id │  └───────────────┘
                               │               │
                               │ Agent polls   │
                               │ for decision  │
                               └───────┬───────┘
                                       │
                          ┌────────────┴────────────┐
                          │                         │
                          ▼                         ▼
                   ┌─────────────┐          ┌─────────────┐
                   │  APPROVED   │          │  REJECTED   │
                   │             │          │             │
                   │ Forward to  │          │ Return 403  │
                   │ target      │          │ to agent    │
                   └─────────────┘          └─────────────┘
```

### System Components

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────────┐
│  AI Agent   │────▶│  Sentinel   │────▶│   Target    │     │    External     │
│             │◀────│   Gateway   │◀────│   Systems   │     │    Services     │
└─────────────┘     └──────┬──────┘     └─────────────┘     └────────┬────────┘
                           │                                         │
              ┌────────────┼────────────┐                            │
              │            │            │                            │
              ▼            ▼            ▼                            │
        ┌──────────┐ ┌──────────┐ ┌──────────┐                      │
        │  Redis   │ │PostgreSQL│ │Prometheus│                      │
        │          │ │          │ │          │                      │
        │• Policies│ │• Audit   │ │• Metrics │                      │
        │• Cache   │ │  Logs    │ │• Alerts  │                      │
        │• Rate    │ │• History │ │          │                      │
        │  Limits  │ │          │ │          │                      │
        └──────────┘ └──────────┘ └──────────┘                      │
                                                                     │
                                                    ┌────────────────┘
                                                    │
                                                    ▼
                                           ┌───────────────┐
                                           │   Approval    │
                                           │   Service     │
                                           │               │
                                           │ • Slack       │
                                           │ • Email       │
                                           │ • Custom UI   │
                                           │ • PagerDuty   │
                                           └───────────────┘
```

---

## How It Works

### 1. Agent Sends Request
```bash
curl -X POST http://sentinel:8000/api/v1/gateway/evaluate \
  -H "Authorization: Bearer agent_sk_..." \
  -d '{
    "agent_id": "refund-bot",
    "action_type": "refund",
    "target_resource": "payments/refund",
    "parameters": {"amount": 750, "customer_ssn": "123-45-6789"}
  }'
```

### 2. Sentinel Processes
1. ✅ Validates API key
2. ✅ Checks rate limits
3. ✅ Evaluates against policies (refund > $500 = high risk)
4. ✅ Sanitizes PII (SSN masked in logs)
5. ✅ Calculates risk score
6. ✅ Makes decision

### 3. Response to Agent

**If ALLOWED** (risk < 0.8):
```json
{
  "status": "allowed",
  "decision": "allow",
  "message": "Request approved",
  "risk_level": "low",
  "forwarded": true,
  "target_response": { "refund_id": "ref_123", "status": "processed" }
}
```

**If DENIED** (risk ≥ 1.0):
```json
{
  "status": "denied",
  "decision": "deny",
  "message": "Request denied: Amount $750 exceeds limit of $500",
  "risk_level": "high",
  "matched_policies": ["refund_limit_500"]
}
```

**If PENDING APPROVAL** (0.8 ≤ risk < 1.0):
```json
{
  "status": "pending_approval",
  "decision": "pending",
  "message": "High-risk action requires human approval",
  "approval_id": "apr_abc123",
  "approval_url": "https://approvals.company.com/apr_abc123"
}
```

### 4. What the Agent Does Next

| Decision | Agent Action |
|----------|--------------|
| **ALLOW** | Proceed with response from target system |
| **DENY** | Inform user, modify request, or escalate |
| **PENDING** | Poll `/api/v1/approvals/{id}` or wait for webhook callback |

---

## Features

### 🔐 Zero-Trust Authentication
- Every request requires valid API key (`agent_sk_` prefix)
- Per-agent permissions and rate limits
- Keys can be revoked instantly

### 🧠 Dynamic Policy Engine
- Update policies via API—no restart needed
- Policies cached in Redis for sub-millisecond evaluation
- Supports: amount limits, protected resources, time-based rules, bulk operation limits

### 🔒 PII Sanitization
- Microsoft Presidio detects 15+ PII types
- Automatic masking before logging
- Original data forwarded to target (if allowed), sanitized data logged

**Detected PII Types:**
- SSN, Credit Cards, Bank Accounts
- Email, Phone, IP Address
- Names, Addresses
- Passport, Driver's License
- Medical License, IBAN, Crypto Addresses

### ⚡ Circuit Breaker Modes

| Mode | Behavior | Use Case |
|------|----------|----------|
| **SHADOW** | Log decisions but always allow | Safe onboarding, testing |
| **ENFORCE** | Actually block/approve based on policies | Production |

Switch modes at runtime:
```bash
curl -X PUT "http://sentinel:8000/api/v1/gateway/mode?mode=SHADOW"
```

### 👥 Human-in-the-Loop Approvals
- High-risk actions (0.8 ≤ risk < 1.0) trigger approval workflow
- Webhook sends request to your approval service (Slack, email, custom UI)
- Agent receives 202 with `approval_id` to poll
- Approved requests are forwarded; rejected requests return 403

### 📊 Observability
- **Prometheus metrics**: Request counts, latency percentiles, risk distribution
- **Structured JSON logs**: Ready for Datadog, Splunk, ELK
- **Audit trail**: Every request logged to PostgreSQL with full context

---

## Quick Start

### Prerequisites
- Docker & Docker Compose
- 4GB+ RAM

### Start the Stack

```bash
# Extract and navigate
cd sentinel-gateway

# Start all services
docker-compose up -d

# Check health
curl http://localhost:8000/health
```

### Test a Request

```bash
# This will be DENIED (amount > $500 limit)
curl -X POST http://localhost:8000/api/v1/gateway/evaluate \
  -H "Authorization: Bearer agent_sk_test_key_12345678901234567890" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "support-bot",
    "action_type": "refund",
    "target_resource": "payments/refund",
    "parameters": {"amount": 750}
  }'
```

### Start with Monitoring

```bash
docker-compose --profile monitoring up -d

# Access:
# - Gateway: http://localhost:8000
# - Prometheus: http://localhost:9090
# - Grafana: http://localhost:3000 (admin/sentinel)
```

---

## Default Policies

| Rule ID | Trigger | Risk Score | Effect |
|---------|---------|------------|--------|
| `refund_limit_500` | Refund > $500 | +0.4 | Likely denied |
| `payment_limit_10000` | Payment > $10,000 | +0.3 | May need approval |
| `admin_action_high_risk` | Any admin action | +0.6 | Flagged high-risk |
| `user_data_access` | Access user data | +0.3 | Requires justification |
| `database_write_protection` | Write to users/payments/credentials tables | +0.5 | Protected |
| `bulk_operation_limit` | Affect > 1000 rows | +0.35 | Limited |

Risk scores are cumulative. A request matching multiple policies may exceed thresholds.

---

## API Reference

### Core Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/gateway/evaluate` | POST | Evaluate agent request |
| `/api/v1/gateway/mode` | GET/PUT | Get or set gateway mode |
| `/api/v1/policies` | GET/POST | List or create policies |
| `/api/v1/policies/{id}` | GET/DELETE | Get or delete policy |
| `/api/v1/approvals/{id}` | GET | Check approval status |
| `/api/v1/audit/logs` | GET | Query audit logs |
| `/health` | GET | Health check |
| `/metrics` | GET | Prometheus metrics |

### Authentication

All endpoints (except `/health`, `/metrics`) require:
```
Authorization: Bearer agent_sk_<key>
```

Test keys:
- `agent_sk_test_key_12345678901234567890`
- `agent_sk_demo_key_abcdefghijklmnopqrst`

---

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SENTINEL_GATEWAY_MODE` | `SHADOW` | `SHADOW` or `ENFORCE` |
| `SENTINEL_RISK_SCORE_APPROVAL_THRESHOLD` | `0.8` | Score requiring human approval |
| `SENTINEL_RISK_SCORE_BLOCK_THRESHOLD` | `1.0` | Score for automatic denial |
| `SENTINEL_RATE_LIMIT_REQUESTS` | `1000` | Requests per window |
| `SENTINEL_RATE_LIMIT_WINDOW_SECONDS` | `60` | Rate limit window |
| `SENTINEL_APPROVAL_WEBHOOK_URL` | - | URL for approval notifications |
| `SENTINEL_REDIS_HOST` | `localhost` | Redis hostname |
| `SENTINEL_POSTGRES_HOST` | `localhost` | PostgreSQL hostname |

---

## Integration Patterns

### Pattern 1: Transparent Proxy
Agent doesn't know about Sentinel. Configure agent's target URL to point to Sentinel.

```
Agent → Sentinel → Actual API
```

### Pattern 2: Explicit Gateway
Agent explicitly calls Sentinel for policy evaluation before acting.

```python
# Agent code
response = sentinel.evaluate(action="refund", amount=500)
if response.decision == "allow":
    payment_api.refund(amount=500)
elif response.decision == "pending":
    await wait_for_approval(response.approval_id)
else:
    notify_user("Refund requires manager approval")
```

### Pattern 3: Sidecar
Deploy Sentinel as a sidecar container in Kubernetes, intercepting all egress traffic.

---

## Project Structure

```
sentinel-gateway/
├── app/
│   ├── main.py              # FastAPI application & endpoints
│   ├── config.py            # Environment configuration
│   ├── models.py            # Pydantic request/response models
│   ├── middleware.py        # Auth, rate limiting, logging
│   ├── policy_engine.py     # Policy evaluation & PII sanitization
│   ├── circuit_breaker.py   # Shadow/enforce decision logic
│   ├── database.py          # PostgreSQL audit logging
│   ├── redis_client.py      # Redis caching & rate limits
│   └── metrics.py           # Prometheus metrics
├── scripts/
│   ├── init-db.sql          # Database schema
│   ├── mock_approval_service.py  # Test approval webhook
│   └── prometheus.yml       # Prometheus config
├── Dockerfile
├── docker-compose.yml
└── README.md
```

---

## Security Considerations

- **PII Protection**: All sensitive data masked before logging
- **API Key Rotation**: Implement regular key rotation in production
- **TLS**: Use a reverse proxy (nginx, Traefik) for HTTPS
- **Secrets Management**: Use Vault, AWS Secrets Manager, or similar
- **Audit Integrity**: Consider append-only tables or write-once storage
- **Network Isolation**: Deploy in private subnet, expose only via load balancer

---

## Roadmap

- [ ] OAuth2/OIDC support for agent authentication
- [ ] Policy versioning and rollback
- [ ] ML-based anomaly detection
- [ ] Multi-region deployment support
- [ ] Terraform/Helm deployment templates
- [ ] SDK libraries (Python, Node.js, Go)

---

## License

MIT License - See LICENSE file for details.

---

## Contributing

Contributions welcome! Please read CONTRIBUTING.md for guidelines.