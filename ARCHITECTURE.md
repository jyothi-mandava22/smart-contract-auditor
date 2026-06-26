# Architecture: Full-Stack Extension Plan

This document outlines how the Smart Contract Auditor MVP (Streamlit + Gemini) 
scales into a production-grade full-stack application.

---

## Current MVP Architecture

```
Browser (Streamlit)
      │
      ▼
  app.py (UI layer)
      │
      ▼
  auditor.py (business logic)
      │
      ▼
  Gemini 1.5 Flash API (AI layer)
```

---

## Target Full-Stack Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   FRONTEND (Next.js 14)                 │
│  Monaco Editor  │  Dashboard  │  Auth (NextAuth.js)     │
└──────────────────────────┬──────────────────────────────┘
                           │ REST / JSON
┌──────────────────────────▼──────────────────────────────┐
│                  BACKEND (FastAPI)                       │
│  POST /api/v1/audit    → submit contract (returns job_id)│
│  GET  /api/v1/audit/{id} → poll job status              │
│  GET  /api/v1/audit/{id}/report → download report       │
│  GET  /api/v1/history  → user's past audits             │
└────────────┬──────────────────────────┬─────────────────┘
             │                          │
┌────────────▼────────┐    ┌────────────▼──────────────┐
│  Celery + Redis     │    │  PostgreSQL + SQLAlchemy  │
│  (async job queue)  │    │  (audit history + users)  │
└────────────┬────────┘    └───────────────────────────┘
             │
┌────────────▼────────┐
│  Gemini 1.5 Flash   │
│  (AI audit engine)  │
└─────────────────────┘
```

---

## Phase 2 — FastAPI Backend (Weeks 1–2 after internship)

### Endpoints

```
POST   /api/v1/audit              Submit contract, returns {job_id}
GET    /api/v1/audit/{job_id}     Poll status: pending / running / complete / failed
GET    /api/v1/audit/{job_id}/report   Return AuditReport JSON or PDF
GET    /api/v1/history            Paginated user audit history
DELETE /api/v1/audit/{job_id}     Delete an audit record
```

### Why Celery + Redis?
Gemini audits on large contracts take 5–15 seconds. Blocking the HTTP request
is unacceptable. The correct pattern:
1. POST /audit → immediately returns job_id
2. Celery worker picks up the job, runs audit_contract()
3. Frontend polls GET /audit/{job_id} every 2s until status = "complete"

This is the async job queue pattern used by every production AI API.

### Database Schema (PostgreSQL)

```sql
-- Users
CREATE TABLE users (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email       VARCHAR(255) UNIQUE NOT NULL,
    github_id   VARCHAR(100),
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- Audits
CREATE TABLE audits (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID REFERENCES users(id),
    contract_hash   VARCHAR(64),      -- SHA-256 of contract code (dedup cache)
    contract_name   VARCHAR(255),
    status          VARCHAR(20),      -- pending / running / complete / failed
    risk_score      FLOAT,
    risk_label      VARCHAR(50),
    findings_json   JSONB,
    summary         TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);
```

**Key benefit:** `contract_hash` lets you cache audits — if the same contract
is submitted twice, return the cached result instantly.

---

## Phase 3 — React/Next.js Frontend (Weeks 3–4)

### Key Components

- **Monaco Editor** — VSCode's editor (MIT license, open source)
  - Syntax highlighting for Solidity
  - Line numbers, minimap, keyboard shortcuts
  - Inline decorations to highlight vulnerable lines

- **Inline Vulnerability Annotations**
  ```js
  // After audit completes, add red squiggle at specific lines
  editor.deltaDecorations([], [{
    range: new monaco.Range(34, 1, 34, 100),
    options: { inlineClassName: 'critical-line', hoverMessage: { value: finding.explanation } }
  }]);
  ```

- **Dashboard** — Audit history, severity trends over time, most common vuln types

- **Auth** — NextAuth.js with GitHub OAuth
  (GitHub OAuth fits the developer audience natively)

---

## Phase 4 — Advanced Features

### Multi-file Contract Support
Real DeFi contracts import from multiple files. Parse Solidity `import` statements,
resolve local paths, concatenate into a single audit payload.

### Diff Auditor
Upload v1 and v2 of a contract. Show only *new* vulnerabilities introduced.
Useful for auditing upgrades and patches.

### False Positive Feedback Loop
Users mark findings as false positives → store in PostgreSQL →
use as negative few-shot examples in future Gemini prompts.
This is a primitive RLHF loop.

### GitHub App Integration
Trigger an audit automatically on every PR that modifies `.sol` files.
Post findings as a PR review comment.

---

## Docker Compose (Local Dev)

```yaml
version: "3.9"
services:
  api:
    build: ./backend
    ports: ["8000:8000"]
    environment:
      - DATABASE_URL=postgresql://user:pass@db:5432/auditor
      - REDIS_URL=redis://redis:6379
      - GEMINI_API_KEY=${GEMINI_API_KEY}
    depends_on: [db, redis]

  worker:
    build: ./backend
    command: celery -A tasks worker --loglevel=info
    depends_on: [redis]

  frontend:
    build: ./frontend
    ports: ["3000:3000"]

  db:
    image: postgres:16
    environment:
      POSTGRES_DB: auditor
      POSTGRES_USER: user
      POSTGRES_PASSWORD: pass

  redis:
    image: redis:7-alpine
```

---

## Deployment

| Service | Platform | Free tier |
|---|---|---|
| FastAPI | Railway or Render | Yes |
| Next.js | Vercel | Yes |
| PostgreSQL | Railway or Supabase | Yes |
| Redis | Upstash | Yes (10k req/day) |
| Domain | Cloudflare | Free proxy |
