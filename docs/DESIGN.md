# Vouch — Self-Hosted SMTP Email Verification Platform
### Engineering Design & Architecture Proposal

> **Status:** Draft for review · **Author role:** Founding maintainer / principal engineer
> **Stewarded by:** TrySelfHost · **Target license:** Apache-2.0 (core) · **Working codename:** `vouch`
> *("Vouch" is a placeholder — it vouches for whether an address will accept mail. Alternatives worth registering: `verity`, `reachd`, `sift`. Pick one before the first public tag; renaming a Go module after `v1` is painful.)*

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Vision](#2-vision)
3. [Prior Art & Ecosystem Research](#3-prior-art--ecosystem-research)
4. [Architecture Review of the Existing Prototype](#4-architecture-review-of-the-existing-prototype)
5. [Proposed Architecture](#5-proposed-architecture)
6. [System Diagrams](#6-system-diagrams)
7. [Service & Module Responsibilities](#7-service--module-responsibilities)
8. [API Design](#8-api-design)
9. [Database Design](#9-database-design)
10. [Queue Design](#10-queue-design)
11. [Worker Design](#11-worker-design)
12. [Egress & Reputation Management (the core differentiator)](#12-egress--reputation-management)
13. [Monitoring & Observability](#13-monitoring--observability)
14. [Security Model](#14-security-model)
15. [Scaling Strategy (100k → 100M/day)](#15-scaling-strategy)
16. [Technology Stack — Decisions & Trade-offs](#16-technology-stack)
17. [Open-Source Repository Structure](#17-open-source-repository-structure)
18. [CI/CD Pipeline](#18-cicd-pipeline)
19. [Development Workflow & Contributor DX](#19-development-workflow)
20. [Documentation Strategy](#20-documentation-strategy)
21. [Governance Model](#21-governance-model)
22. [Roadmap — MVP / v1 / Future](#22-roadmap)
23. [Risks & Trade-offs](#23-risks--trade-offs)
24. [Migration Plan from the Current Prototype](#24-migration-plan)
25. [Future Enhancements](#25-future-enhancements)

---

## 1. Executive Summary

The open-source ecosystem already has good **verification *engines*** — Reacher (Rust) and AfterShip's email-verifier (Go) both do syntax, DNS/MX, disposable/role checks, and SMTP catch-all probing well. What the ecosystem **does not** have is a trustworthy, self-hostable **verification *platform*** that sits above an engine and solves the problems that actually determine accuracy and cost at scale:

- **Egress reputation management** — the single biggest determinant of SMTP-probe accuracy. Every engine's docs concede the same thing: the moment your sending IP is flagged, results degrade sharply. No OSS project treats egress identities (IP + rDNS/PTR + HELO + proxy) as a managed, health-scored, first-class resource with warm-up, quarantine, and routing policy.
- **Provider-aware verification policy** — Gmail, Yahoo, and Microsoft either block probing or return uninformative results. A production platform must *know this* and route around it (skip / statistical / API), rather than pretending an `unknown` from Gmail is a verification failure.
- **Orchestration & observability** at bulk scale — dedup, a cheap-to-expensive filter funnel, per-destination rate limiting, retry/greylist scheduling, and Prometheus/Grafana-grade observability — packaged so a two-person shop *or* a 100M/day operation can run it.

**Thesis:** *Do not rebuild the verification engine. Build the platform the engines don't provide, and make the engine pluggable.*

Concretely, this proposal recommends:

| Decision | Choice | One-line rationale |
|---|---|---|
| Topology | **Modular monolith control plane + stateless worker fleet + message bus** | Single-binary simplicity for small deploys; independent horizontal scaling of the probe tier. Not microservices. |
| Language | **Go** (control plane + workers) | Lingua franca of this ecosystem (k8s, Prometheus, Grafana, Gitea, Listmonk); great concurrency; the MIT engine is already Go. |
| Default engine | **email-verifier (MIT), linked in-process** | Permissive license keeps the core Apache-2.0 and the binary self-contained. |
| Optional engine | **Reacher (AGPL), out-of-process adapter** | Kept at arm's length so its copyleft never taints the core; users who want it opt in. |
| Bus | **Redis Streams default, NATS JetStream for scale** | Zero extra dependency for small deploys (Redis is already present); JetStream when volume demands it. |
| System of record | **PostgreSQL**; **ClickHouse** optional for analytics at 10M+/day | Boring, reliable, universal; ClickHouse only where append-heavy result analytics justifies it. |
| Cache / rate limit | **Redis** | MX + catch-all + disposable + result caches, token-bucket limiters, small-mode queue. |
| Observability | **Prometheus + Grafana + OpenTelemetry** | Reuse the standard stack; ship dashboards, don't build monitoring. |
| License | **Apache-2.0 core**, **DCO** for contributions | Enterprise-friendly, patent grant, no CLA friction. |

The rest of this document is the implementation-ready specification behind these decisions.

---

## 2. Vision

> **Vouch is the self-hosted platform for verifying email deliverability at any scale, engine-agnostic and reputation-aware, that a small team can run on one VPS and a large team can run on Kubernetes — without either one becoming an expert in IP reputation.**

Design tenets, in priority order:

1. **Accuracy is a reputation problem, not a code problem.** The platform's primary job is to protect and route egress reputation so that the engine's answers are *trustworthy*. Everything else is plumbing.
2. **Honest `unknown`.** We never dress up an unreliable result as a verdict. A Gmail address we can't probe is reported as `risky/unknown` with a machine-readable reason, not `invalid`.
3. **Single binary, no lock-in.** `docker run vouch/vouch` + Postgres + Redis must give a working system in minutes. Every heavier dependency (NATS, ClickHouse, Reacher) is *opt-in* behind a stable interface.
4. **Engine-agnostic.** The verification engine is a plugin. We ship a permissive default and support others.
5. **Contributor-first.** A newcomer clones, runs `make dev`, and has a full stack with a mock SMTP server and seed data in under five minutes. This is a hard requirement, not a nicety.
6. **Operable by default.** Metrics, traces, structured logs, health/readiness endpoints, and Grafana dashboards ship with v1 — not "later."

Explicit non-goals: we are **not** building a hosted SaaS, a paid verification service, a general MTA/mail server, or a data-selling business. The reference deployment is one you run yourself.

---

## 3. Prior Art & Ecosystem Research

### 3.1 What already exists

**Verification engines (the core probe logic):**

- **Reacher / `check-if-email-exists`** (Rust) — the most capable OSS full-stack verifier: syntax, MX, SMTP handshake, catch-all, disposable detection. Its own backend already ships a stateless API tier + worker pool over RabbitMQ + Postgres + a SOCKS5 proxy pool + a `rules.json` for per-domain/per-MX behaviour. **Licensing is the catch: AGPL-3.0 with a separate commercial license.** For a network-served product that wants a permissive core, AGPL is viral across the network boundary — a hard constraint we design around, not against.
- **AfterShip `email-verifier`** (Go, **MIT**) — syntax, MX, misc checks (free/role/disposable), SMTP + catch-all, SOCKS5 proxy support. Less battle-hardened than Reacher on edge cases, but permissively licensed and *already in Go*. This is our default engine.
- **Truemail** (Ruby; `truemail-go` port) — layered regex→DNS→SMTP pipeline. Notable for **host-audit features** (IP / DNS / PTR audits) aimed at diagnosing self-hosted SMTP failures — a good source of ideas for our egress diagnostics.
- **Deep Email Validator** (Node), **validator.js** (syntax), **email-validator** (Python) — mostly syntax/MX layers; not scale platforms.
- **Trumail** (Go) — an older "verification API" service; effectively unmaintained, but a useful reference for the API-service shape.

**Reusable data & tooling:**

- **`FGRibreau/mailchecker`** — cross-language disposable-domain database (55k+ throwaway providers). Vendor the list, refresh on a schedule.
- **`smtpmock`** (Go) — scriptable fake SMTP server; ideal for deterministic integration tests and local dev.
- **Mailpit / MailHog** — SMTP capture tools for dev environments.
- **DNSBL feeds** (Spamhaus ZEN, etc.) and **Postmaster / SNDS**-style provider signals for reputation input.

**Infrastructure primitives we will *reuse*, not rebuild:** Prometheus, Grafana, OpenTelemetry, NATS/Redis, PostgreSQL, ClickHouse, Vault/External-Secrets. Building bespoke monitoring or queueing here would be the classic OSS mistake.

### 3.2 What remains unsolved

Two things are true across *every* engine's own documentation:

1. **Catch-all is the wall.** A catch-all MX returns `250 OK` for any local-part, so per-mailbox SMTP verification is impossible for those domains. Every tool hits this; none *manage* it well (cache the catch-all verdict per domain, expose it honestly, and stop wasting probes on it).
2. **Reputation decay is inevitable and unmanaged.** Accuracy is excellent while your IP is clean and "drops off a cliff" once it's flagged — and it *will* be flagged. Engines expose a proxy setting and stop there. Nobody ships the reputation lifecycle: pool health, warm-up curves, DNSBL monitoring, per-destination circuit breakers, quarantine/rotation, and reputation-aware routing.

Additional gaps: no engine ships **provider-class routing policy** (probe vs skip vs statistical vs API per provider) as first-class config; none ship **bulk-scale orchestration** (dedup, funnel, greylist-aware retry scheduling) as an operable platform; none ship **observability** worthy of production.

### 3.3 Where Vouch genuinely contributes

The defensible, novel surface is the **platform layer between "an engine" and "a production deployment"**:

- A **reputation-managed egress control plane** (§12) — the headline feature.
- A **provider-policy engine** that encodes the uncomfortable truths about consumer providers and routes accordingly (§11.4).
- **Engine-agnostic** orchestration with a permissive default and AGPL-isolated Reacher support (§7, §16).
- **Operable, observable, self-hostable** packaging from one VPS to a Kubernetes fleet (§13, §15).

Everything the engines already do well (the actual SMTP conversation, catch-all detection heuristics), we consume through a stable interface rather than reimplement.

---

## 4. Architecture Review of the Existing Prototype

**Current shape:** `Custom Frontend → Verification API → N × Reacher Workers`, with the frontend distributing jobs across workers; each worker independently runs Reacher SMTP verification.

This got a real business need shipped, and the instincts are right (separate the probe tier; scale workers horizontally). But as a long-term OSS platform it has specific, nameable problems:

| # | Problem | Consequence | Addressed in |
|---|---|---|---|
| P1 | **Frontend is the dispatcher.** Job distribution logic lives in the UI/API layer. | Scheduling can't evolve independently; no headless/API-only operation; the "brain" is coupled to the "face." | §5, §7 (dispatcher becomes a control-plane service) |
| P2 | **Engine is hard-wired to Reacher.** | AGPL exposure for a network-served product; no permissive default; can't A/B engines or add provider-API backends. | §7 (engine port), §16 |
| P3 | **No egress reputation model.** IPs/proxies are used until they degrade; "list-size vs IP-age" blacklist incidents are diagnosed *after the fact*. | Accuracy silently craters; no warm-up, no quarantine, no routing. | §12 |
| P4 | **Push-based, in-memory distribution.** No durable queue between API and workers (or a thin one). | Lost jobs on crash; no backpressure; no replay; hard to reason about at-least-once semantics. | §10 |
| P5 | **Weak observability.** Throughput/acceptance/reputation aren't first-class metrics. | You learn about a burned IP from falling accuracy, not a dashboard. | §13 |
| P6 | **No cheap-to-expensive funnel as an explicit stage.** Probes fire on addresses that syntax/MX/dedup should have eliminated. | Wasted probes = wasted reputation = the scarcest resource spent on garbage. | §11.2 |
| P7 | **Provider handling is implicit.** Consumer-provider skip logic exists but isn't a declared policy surface. | Hard to reason about, tune, or contribute to. | §11.4 |

**The most important review finding:** the prototype optimizes the *cheap* resource (worker compute) and leaves the *scarce* resource (trustworthy egress) unmanaged. The redesign inverts this. Compute is elastic; a clean IP that isn't on Spamhaus is not.

---

## 5. Proposed Architecture

### 5.1 Topology decision — modular monolith + worker fleet

The prompt admires PocketBase, Gitea, Listmonk, Coolify — and the tell is that **they are single (or near-single) binaries**. That is the right instinct for something people must self-host. Full microservices would wreck self-hostability and contributor onboarding for no benefit at the scale of *one team's* verification infrastructure.

**Decision:** a **modular monolith control plane** (one Go binary, internally partitioned into modules with clean ports) **plus a stateless worker fleet** (a second Go binary) connected by a **message bus**. Two deployable artifacts, not twelve.

- **Control plane (`vouch-server`)** — API, auth, job orchestration, scheduler/dispatcher, egress & reputation manager, provider-policy engine, admin UI (embedded), metrics. Internally modular (hexagonal), but deployed as one process. Horizontally scalable behind a load balancer; leader-elected components (scheduler, reputation reconciler) use a lease.
- **Worker (`vouch-worker`)** — stateless probe executor. Pulls verification tasks from the bus, runs the engine against a supplied egress identity, reports results + egress signals back. Scale to N; kill any one at any time.

**Why not microservices?** Because our module boundaries (ingestion, pipeline, scheduling, egress, results, policy) don't have independent scaling profiles *except* the probe executor — and that's exactly the one thing we *do* split out (the worker). This is "split the one axis that actually scales differently, keep the rest together." The internal ports are drawn cleanly (hexagonal/ports-and-adapters) so that *if* a module ever needs to become its own service, the seam already exists. We pay the microservices tax only when a real scaling signal forces it — never speculatively.

### 5.2 Architectural styles applied (and rejected)

| Style | Verdict | Where / why |
|---|---|---|
| **Modular monolith** | **Adopt** | Control plane. Simplicity of deploy; clean internal modules. |
| **Hexagonal / ports-and-adapters** | **Adopt** | Every external concern (engine, bus, store, cache, egress transport, DNSBL) is a port with swappable adapters. This *is* how we get "engine-agnostic," "bus-agnostic," "cloud-agnostic." |
| **Event-driven** | **Adopt, selectively** | Between control plane and workers, and for result fan-out (webhooks, analytics sink). Not as a religion — synchronous calls where a request/response is clearer. |
| **API-first** | **Adopt** | OpenAPI 3.1 is the source of truth; server stubs + SDKs generated from it. |
| **Plugin architecture** | **Adopt** | Engines, provider policies, egress providers (proxy sources), and result sinks are plugins (Go interfaces + out-of-process gRPC option). |
| **CQRS** | **Partial / light** | Reads for analytics hit ClickHouse (or a read model); writes go through Postgres. Full CQRS with separate command/query models is overkill for MVP; we adopt the *read/write store split* only, and only at scale. |
| **DDD (tactical)** | **Light** | Use the ubiquitous language (Job, Task, Verdict, EgressIdentity, ProviderPolicy) and aggregate boundaries; skip the heavy machinery (no event-sourcing, no elaborate aggregates). Justified because the domain has genuinely tricky invariants (reputation lifecycle) worth modeling explicitly. |
| **Full microservices** | **Reject** | No independent scaling need beyond the worker; kills self-host DX. |
| **Event sourcing** | **Reject (for now)** | The audit value doesn't justify the operational cost; an append-only `events` table + ClickHouse gives 90% of the benefit. |

### 5.3 Data flow (single verification, end to end)

```
submit ─▶ ingest ─▶ [FUNNEL: syntax → normalize/dedup → cache lookup →
                     DNS/MX → disposable/role/free → typo/gibberish]
             │                        │
             │ (verdict decided       │ (survivors need an SMTP probe)
             │  cheaply, no probe)     ▼
             │                 SCHEDULER/DISPATCHER
             │                 (per-domain rate limit, greylist calendar,
             │                  provider policy → probe/skip/statistical)
             │                        │  selects EGRESS IDENTITY via
             │                        │  REPUTATION MANAGER (best IP/proxy
             │                        │  for THIS destination provider)
             │                        ▼
             │                   enqueue Task ──▶ BUS ──▶ WORKER
             │                                              │ engine probe
             │                                              │ (MAIL FROM/RCPT TO)
             │                        ┌─────────────────────┘
             │                        ▼
             │                 result + egress signals
             │                 (accepted? tempfail? "blocked"? blacklist hint?)
             ▼                        │
         RESULT STORE ◀───────────────┤──▶ REPUTATION MANAGER (update egress health)
             │                        │
             ├──▶ webhook / SSE fan-out (job progress, per-address verdicts)
             └──▶ analytics sink (ClickHouse) + Prometheus metrics
```

The critical loop is the dotted one: **every probe result feeds the reputation manager**, which adjusts egress health, which changes future routing. That feedback loop is the product.

---

## 6. System Diagrams

### 6.1 Overall system (deployment view)

```
                                  ┌───────────────────────────────────────────┐
   Clients                        │              CONTROL PLANE                 │
   (API / SDK / UI)               │              vouch-server (Go)             │
        │                         │                                           │
        ▼                         │  ┌─────────┐  ┌──────────────┐             │
  ┌───────────┐   HTTPS/REST      │  │  API /  │  │  Ingestion + │             │
  │  Reverse  │──────────────────▶│  │ Gateway │─▶│   Funnel     │             │
  │  Proxy /  │   (OpenAPI 3.1)   │  │ + Auth  │  │  Pipeline    │             │
  │  Ingress  │◀─── SSE/webhooks ─│  └─────────┘  └──────┬───────┘             │
  └───────────┘                   │        │             │                     │
        ▲                         │        ▼             ▼                     │
        │ embedded SPA            │  ┌──────────────────────────────┐          │
        └─────────────────────────│─▶│  Scheduler / Dispatcher      │          │
                                  │  │  Provider-Policy Engine      │          │
                                  │  └──────────┬───────────────────┘          │
                                  │             │            ▲                 │
                                  │             ▼            │ health/route     │
                                  │  ┌──────────────────────────────┐          │
                                  │  │  Egress & Reputation Manager │          │
                                  │  └──────────────────────────────┘          │
                                  │        │            │           │          │
                                  └────────┼────────────┼───────────┼──────────┘
                                           │            │           │
                    ┌──────────────────────┘            │           └───────────┐
                    ▼                                    ▼                       ▼
             ┌────────────┐                     ┌────────────────┐      ┌────────────────┐
             │  MESSAGE   │                     │   PostgreSQL   │      │     Redis      │
             │    BUS     │                     │ (system of     │      │  cache + rate  │
             │ Redis Str. │                     │   record)      │      │  limit + small │
             │ / NATS JS  │                     │  + ClickHouse* │      │   -mode bus    │
             └─────┬──────┘                     └────────────────┘      └────────────────┘
                   │  tasks                              ▲   * optional analytics store
                   ▼                                     │ results / egress signals
        ┌─────────────────────────────────────────┐     │
        │             WORKER FLEET                 │─────┘
        │            vouch-worker × N (stateless)  │
        │  ┌────────────────────────────────────┐  │        ┌─────────────────────────┐
        │  │  Engine Port                       │  │  probes │  EGRESS TRANSPORTS      │
        │  │  ├─ builtin (email-verifier, MIT)  │──┼────────▶│  local IP(s) / rDNS     │
        │  │  ├─ reacher (AGPL, out-of-process) │  │  :25    │  SOCKS5 proxy pool      │
        │  │  └─ provider-api / mock            │  │         │  residential proxies    │
        │  └────────────────────────────────────┘  │         └───────────┬─────────────┘
        └─────────────────────────────────────────┘                     │
                                                                          ▼
                                                              destination MX servers
                                                              (Gmail, corp mail, self-hosted…)

        Observability plane (scrapes/receives from every box above):
        Prometheus ──▶ Grafana        OTel Collector ──▶ traces        stdout JSON ──▶ Loki*
```

### 6.2 Engine plugin architecture

```
                       ┌──────────────────────────────────────┐
   vouch-worker ──────▶│         VerificationEngine (port)     │
                       │  Verify(ctx, Task, Egress) → Verdict  │
                       └───────┬───────────┬───────────┬───────┘
                               │           │           │
              in-process ┌─────▼────┐  ┌────▼─────┐  ┌──▼──────────┐  out-of-process
              (linked)   │ builtin  │  │  reacher │  │ provider-api│  (gRPC/HTTP,
                         │ (MIT,    │  │ (AGPL,   │  │ (Postmaster,│   AGPL isolated)
                         │  Go)     │  │ adapter) │  │  Bounce…)   │
                         └──────────┘  └──────────┘  └─────────────┘
     Apache-2.0 core ────┘   default        opt-in         future
```

The Reacher adapter speaks to Reacher's own HTTP backend or a subprocess over a stable, general-purpose interface — a separate program communicating at arm's length — so the AGPL obligation stays contained to that optional component and never reaches into the Apache-2.0 core. *(This is an engineering boundary chosen for license hygiene; it is not legal advice — the project ships a LICENSING.md and recommends counsel for commercial Reacher use.)*

### 6.3 Reputation feedback loop

```
   ┌────────────┐   pick best egress    ┌─────────────────────┐
   │ Scheduler  │──────for destination─▶│ Reputation Manager  │
   └─────┬──────┘◀──── egress handle ───│  · health score/id  │
         │                              │  · warm-up curve    │
         ▼ Task{addr, egress_id}        │  · quarantine set   │
   ┌────────────┐                       │  · DNSBL status     │
   │  Worker    │                       │  · per-dest circuit │
   └─────┬──────┘                       └─────────▲───────────┘
         │ probe                                  │ signals:
         ▼                                        │  accepted / 4xx tempfail /
   destination MX ──── SMTP response ─────────────┘  5xx "blocked" / conn-refused
                                                     + async: DNSBL poll, PTR audit
```

---

## 7. Service & Module Responsibilities

Internal modules of `vouch-server` (each a package with a public interface; wired at startup):

| Module | Responsibility | Key ports (interfaces) it owns/uses |
|---|---|---|
| **api** | HTTP/REST surface, request validation, auth middleware, SSE, webhook dispatch, embedded SPA. | `AuthN`, `AuthZ` |
| **ingestion** | Accept single + bulk submissions (JSON, CSV, streaming upload), create Jobs/Tasks, dedup within a job, enforce quotas. | `JobStore`, `Bus` |
| **pipeline** | The cheap-to-expensive **funnel** (syntax → normalize → cache → DNS/MX → disposable/role/free → typo). Decides which addresses need an SMTP probe. | `Cache`, `Resolver`, `DisposableDB` |
| **scheduler/dispatcher** | Turns "needs-probe" survivors into scheduled Tasks: per-destination rate limiting, greylist retry calendar, provider-policy routing, egress selection, backpressure. Leader-elected. | `Bus`, `RateLimiter`, `ProviderPolicy`, `EgressManager` |
| **egress + reputation** | Own the egress identity pool; score health; warm-up/cool-down/quarantine; DNSBL & PTR audits; per-(egress,destination) circuit breakers; routing decisions. | `EgressStore`, `DNSBL`, `ProxyProvider` |
| **provider-policy** | Declarative rules mapping destination provider/MX → strategy (probe / skip / statistical / api) + tunables. Hot-reloadable; plugin hooks. | `PolicyStore` |
| **results** | Persist verdicts, expose query/read models, fan out to webhooks/SSE/analytics sink, manage result cache + TTLs. | `ResultStore`, `AnalyticsSink`, `Cache` |
| **identity** | API keys, users/orgs, OIDC login for UI, RBAC, quotas. | `AuthN`, `AuthZ` |
| **observability** | Metrics registry, tracing, structured logging, health/readiness. Cross-cutting. | — |
| **admin/ui** | Serve the embedded SPA; admin actions (egress pool mgmt, policy editing, job monitoring). | — |

Worker (`vouch-worker`) modules: **task-consumer** (bus subscription, concurrency control, ack/nack), **engine-runner** (the `VerificationEngine` port + adapters), **egress-binder** (bind the assigned egress identity — bind local IP / dial through the assigned SOCKS5 proxy / set HELO), **signal-reporter** (result + egress signals back onto the bus).

**Design rule:** workers hold **no authoritative state** and make **no policy decisions**. All scheduling, routing, and reputation logic lives in the control plane. A worker is a dumb, replaceable muscle that runs one probe with one assigned egress identity and reports what happened. This is what makes them trivially horizontally scalable and safe to kill.

---

## 8. API Design

**Principles:** API-first (OpenAPI 3.1 is the contract), REST for the public surface, versioned under `/v1`, idempotent submission, async-by-default for bulk with webhook/SSE completion, cursor pagination, RFC 7807 problem+json errors. Internal control-plane↔worker traffic uses the **bus** (messages), not REST.

### 8.1 Public REST surface (v1)

```
Auth:      X-API-Key: <key>            (programmatic)     |  OIDC session (UI)

Single verification
  POST   /v1/verify                    { "email": "...", "options": {...} }
                                       → 200 Verdict (sync, fast path) OR
                                       → 202 {job_id} if the caller requests async

Bulk verification
  POST   /v1/jobs                      body: inline array | CSV upload | presigned ref
                                       → 202 { job_id, counts, status_url }
  GET    /v1/jobs/{id}                 → job status + progress counters
  GET    /v1/jobs/{id}/results         → cursor-paginated verdicts (?status=&cursor=)
  GET    /v1/jobs/{id}/results.csv     → streaming CSV export
  GET    /v1/jobs/{id}/events          → SSE stream (live progress + verdicts)
  POST   /v1/jobs/{id}/cancel          → cancel remaining tasks

Webhooks
  POST   /v1/webhooks                  register endpoint (job.completed, address.verified)
  (delivery is signed HMAC + retried with backoff; dead-letter after N)

Admin / operability  (RBAC: admin)
  GET    /v1/egress                    list egress identities + health scores
  POST   /v1/egress                    add identity (ip|proxy, rdns, helo, provider hints)
  PATCH  /v1/egress/{id}               warm-up/quarantine/enable/disable
  GET    /v1/policies                  provider policies (probe|skip|statistical|api)
  PUT    /v1/policies/{provider}       upsert policy
  GET    /v1/stats                     acceptance rate by provider, probe volume, cache hit
  GET    /healthz  /readyz             liveness / readiness
  GET    /metrics                      Prometheus exposition
```

### 8.2 The Verdict object (stable public schema)

```jsonc
{
  "email": "jane@example.com",
  "normalized": "jane@example.com",
  "status": "deliverable",          // deliverable | undeliverable | risky | unknown
  "sub_status": "valid_mailbox",    // machine-readable reason code (stable enum)
  "confidence": 0.94,               // 0..1, engine + provider-policy derived
  "checks": {
    "syntax":     { "valid": true },
    "mx":         { "found": true, "records": ["..."] },
    "disposable": false,
    "role":       false,
    "free":       false,
    "catch_all":  false,            // domain-level, cached
    "smtp":       { "probed": true, "code": 250, "response": "accepted" }
  },
  "provider": "custom",             // gmail | microsoft | yahoo | custom | ...
  "engine":   "builtin",            // which engine produced the SMTP verdict
  "egress_id":"eg_7f...",           // which egress identity was used (auditability)
  "cached":   false,
  "checked_at": "2026-07-07T10:00:00Z"
}
```

**`status` is deliberately four-valued.** Collapsing to a boolean is the industry's cardinal sin. `risky` (catch-all, role, or provider-we-can't-probe) and `unknown` (tempfail, blocked, greylisted, port-25-unreachable) are honest, distinct outcomes with `sub_status` reason codes — so downstream users decide their own risk tolerance instead of inheriting ours.

### 8.3 Versioning & compatibility

- **URL-versioned** major (`/v1`); additive changes are minor and never break clients; the `sub_status` enum is append-only.
- **OpenAPI spec is the contract**, checked into the repo; a CI job fails the build on a breaking change without a version bump (schema-diff gate).
- **SDKs are generated** (`oapi-codegen` for Go; `openapi-generator` for TS/Python) so they never drift from the spec.
- **Webhook payloads** and **bus message schemas** are versioned independently (protobuf/JSON-schema in `/api`), with at least one minor-version of backward compatibility guaranteed.

---

## 9. Database Design

**System of record: PostgreSQL.** One boring, transactional, universally-understood store. Analytics that would bloat Postgres at high volume go to **ClickHouse** (optional, engaged only at 10M+/day).

### 9.1 Core relational schema (Postgres, abridged)

```sql
-- Tenancy & auth ---------------------------------------------------------
orgs(id, name, created_at)
users(id, org_id, email, oidc_sub, role, created_at)
api_keys(id, org_id, hash, prefix, scopes[], last_used_at, revoked_at)

-- Jobs & tasks -----------------------------------------------------------
jobs(id, org_id, source, total, pending, done, status, options jsonb,
     created_at, completed_at)
tasks(id, job_id, email, normalized, domain, provider,
      state,                    -- queued|probing|done|skipped|deferred
      verdict jsonb,            -- final Verdict (nullable until done)
      attempts int, next_attempt_at,   -- greylist/retry scheduling
      egress_id, created_at, updated_at)
   -- INDEX (job_id, state), (next_attempt_at) WHERE state='deferred',
   --       (domain) for per-domain batching

-- Domain intelligence cache (the probe-savers) --------------------------
domain_cache(domain PK, mx jsonb, mx_provider, is_catch_all,
             catch_all_checked_at, disposable bool, ttl_expires_at)
result_cache(email_hash PK, verdict jsonb, ttl_expires_at)

-- Egress & reputation (the crown jewels) --------------------------------
egress_identities(id, kind,               -- local_ip | socks5 | residential
                  address, rdns, helo_name, asn, region,
                  state,                  -- warming|active|quarantined|disabled
                  warmup_stage, warmup_started_at,
                  daily_cap, used_today,
                  health_score,           -- 0..1 rolling
                  created_at, updated_at)
egress_events(id, egress_id, kind,        -- accepted|tempfail|blocked|dnsbl_hit|reset
              destination_provider, code, detail, at)
egress_circuit(egress_id, destination_provider, state, open_until)  -- breaker per pair
dnsbl_status(egress_id, list, listed bool, checked_at)

-- Policy & audit ---------------------------------------------------------
provider_policies(provider PK, strategy, params jsonb, updated_at, updated_by)
audit_log(id, org_id, actor, action, target, at, meta jsonb)
```

### 9.2 Store design notes & trade-offs

- **`domain_cache` and `result_cache` are the reputation budget.** A cached catch-all verdict or a fresh result means **zero probes**. At scale these caches convert the naive "N probes for N addresses" into "probes only for *novel, probable* addresses" — often a small fraction of input. TTLs are configurable (result cache typically days–weeks; catch-all longer).
- **`tasks.next_attempt_at`** is a first-class column: greylisting and tempfails become *scheduled* retries, not spins. A partial index on deferred tasks keeps the "what's due now" query cheap.
- **Egress state is authoritative in Postgres, hot-mirrored in Redis.** The reputation manager reads/writes Redis for speed (routing is on the hot path) and reconciles to Postgres for durability. Postgres is truth; Redis is cache.
- **`egress_events` is append-only** and is the audit trail for *why* an IP was quarantined — invaluable for the "list-size vs IP-age" class of incident. At high volume this stream is *also* mirrored to ClickHouse for analytics.
- **Migrations:** `goose`/`atlas`, forward-only, one schema file per migration, tested in CI against a real Postgres container.

### 9.3 ClickHouse (optional, ≥10M/day)

Append-only `verifications` and `egress_events` fact tables, partitioned by day, for cheap analytical queries ("acceptance rate by provider by egress ASN over 30 days") that would otherwise hammer Postgres. Engaged by config; the platform runs perfectly without it below ~10M/day.

---

## 10. Queue Design

**The bus is a port with two first-class adapters.** This is how the same codebase serves a one-VPS deploy and a 100M/day fleet.

| Adapter | When | Why |
|---|---|---|
| **Redis Streams** (default) | small/medium (≤ ~1M/day) | **Zero extra dependency** — Redis is already present for cache + rate limiting. Consumer groups give at-least-once with acks. One less thing to run. |
| **NATS JetStream** (scale) | ≥ ~10M/day, multi-node/k8s | Lightweight single binary, durable streams, clustering, excellent throughput and backpressure, cloud-native. The natural scale-out choice. |
| *(Kafka adapter)* | rare, very high volume + existing Kafka | Provided as a community adapter; **not** recommended as a default — operational weight is unjustified for most self-hosters. |

### 10.1 Streams / subjects

```
tasks.probe            work queue: control plane → workers (the SMTP-probe tasks)
tasks.results          workers → control plane (verdicts)
egress.signals         workers → reputation manager (accepted/tempfail/blocked/…)
jobs.events            internal fan-out: progress, completion (→ webhooks/SSE)
tasks.deferred (DLQ)   poison/exhausted-retry tasks for inspection
```

### 10.2 Delivery semantics & trade-offs

- **At-least-once**, with **idempotent workers** (a task carries a stable id; re-delivery re-probes at worst, and result writes are upsert-by-(job_id,email)). Exactly-once is not worth its cost here; a duplicated probe is cheap and safe *because the scheduler already rate-limited it*.
- **Backpressure comes from the scheduler, not the bus.** The scheduler only enqueues as many probe tasks as current egress capacity + per-destination rate limits allow. This is deliberate: the bus should never be the thing holding back a burned IP — the scheduler is, because it owns reputation. The queue is for durability and fan-out, not for rate control.
- **Priority:** a lightweight two-lane scheme (interactive single-verify vs bulk) via separate subjects/consumer groups, so a huge bulk job never starves a live `POST /v1/verify`.

---

## 11. Worker Design

### 11.1 Anatomy

A `vouch-worker` is a stateless loop:

```
for {
  task   := bus.Claim("tasks.probe")          // consumer group, N in flight
  egress := task.Egress                        // ASSIGNED by control plane, not chosen here
  binder := egress.Bind()                      // local-IP bind | SOCKS5 dial | HELO set
  verdict, signals := engine.Verify(ctx, task, binder)   // the SMTP conversation
  bus.Publish("tasks.results", verdict)
  bus.Publish("egress.signals", signals)       // feeds the reputation loop
  bus.Ack(task)
}
```

Concurrency is bounded per worker (config: in-flight probes, per-destination sub-limits mirrored from the scheduler's hints). Workers expose their own `/metrics` and `/healthz`. They are the unit of horizontal scale — HPA on queue depth (§15).

### 11.2 The funnel (why probe volume ≪ input volume)

The pipeline runs **before** any task reaches the probe queue. Each stage is cheaper than the next and can produce a terminal verdict:

```
1. Syntax (RFC 5322)            → invalid  ⟶ done (no probe)         [~free]
2. Normalize + dedup            → collapse gmail dots/+tags, drop dups [~free]
3. Result cache lookup          → hit      ⟶ done (no probe)         [Redis]
4. DNS/MX resolve (+ cache)     → no MX    ⟶ undeliverable (no probe)[DNS/Redis]
5. Disposable / role / free     → flag     ⟶ risky (often no probe)  [in-mem DB]
6. Catch-all cache (per domain) → catch-all⟶ risky (no probe)        [Redis/PG]
7. Provider policy              → skip/statistical/api for consumer providers
   ────────────────────────────────────────────────────────────────
   ONLY survivors reach:  tasks.probe  (the reputation-costly step)
```

**This funnel is the second most important design element after reputation management.** Every address eliminated cheaply is an IP-reputation dollar saved. In practice, syntax/MX/dedup/cache/catch-all/provider-skip can remove the large majority of a typical dirty list before a single SMTP connection is opened.

### 11.3 Engine port

```go
type VerificationEngine interface {
    // Verify runs the SMTP-level check for a single address using the
    // provided egress binding, returning a Verdict and egress Signals.
    Verify(ctx context.Context, t Task, eg EgressBinding) (Verdict, Signals, error)
    Name() string
    Capabilities() Caps   // supports_catch_all, supports_proxy, needs_port25, ...
}
```

Adapters: **builtin** (email-verifier, MIT, in-process, default), **reacher** (AGPL, out-of-process via its HTTP backend/subprocess), **provider-api** (future: Postmaster/feedback signals), **mock** (deterministic, for tests). Selection is per-policy and per-deployment config.

### 11.4 Provider-policy engine (the honesty layer)

Extends Reacher's `rules.json` idea into a first-class, hot-reloadable surface:

```yaml
# policies.yaml (hot-reloaded; also editable via admin API/UI)
default:       { strategy: probe }
gmail:         { strategy: skip,        reason: "catch-all-like; probing unreliable" }
microsoft:     { strategy: statistical, reason: "throttles + blocks probes" }
yahoo:         { strategy: skip }
"*.edu":       { strategy: probe, rate: slow }
catch_all:     { strategy: skip,        emit: risky }
```

- **probe** — full SMTP verification via the engine.
- **skip** — do not probe; emit `risky/unknown` with an honest reason (used for providers where probing is worthless or harmful).
- **statistical** — combine cheap signals (domain reputation, historical acceptance, syntax patterns) into a confidence score without a live probe.
- **api** — defer to a provider-specific signal source where one exists.

Policies ship with sensible defaults for the big consumer providers (informed by the well-documented reality that Gmail/Yahoo/Microsoft don't yield reliable SMTP probes) and are fully overridable.

---

## 12. Egress & Reputation Management

**This is the differentiator. Read this section as the actual product.**

The scarce resource in SMTP verification is not CPU — it's a **trustworthy egress identity**: an (IP, rDNS/PTR, HELO name, optional proxy) tuple that destination mail servers still accept probes from. Reputation decays with use and can be destroyed by one over-aggressive bulk job. Vouch manages the *lifecycle* of that resource.

### 12.1 The egress identity

```
EgressIdentity = {
  kind:    local_ip | socks5 | residential_proxy
  address, rdns (PTR must match forward DNS), helo_name, asn, region
  state:   warming | active | quarantined | disabled
  health_score: 0..1 (rolling, per-destination-provider breakdown)
  warmup_stage, daily_cap, used_today
}
```

### 12.2 Lifecycle state machine

```
        add
         │
         ▼
   ┌──────────┐  warm-up curve complete   ┌──────────┐
   │ WARMING  │──────────────────────────▶│  ACTIVE  │
   │ (ramp    │                           │          │
   │  volume) │◀──── recovered ───────────│          │
   └────┬─────┘                           └────┬─────┘
        │ severe signal                        │ degradation:
        │ (DNSBL hit, mass 5xx block)          │ health < threshold OR
        ▼                                       │ circuit opens for many dests
   ┌──────────────┐◀───────────────────────────┘
   │ QUARANTINED  │  cool-down timer + re-audit (DNSBL clear? PTR ok?)
   └──────┬───────┘
          │ clean after cool-down → back to WARMING (re-ramp, never straight to ACTIVE)
          ▼
   ┌──────────┐  operator disables / permanently burned
   │ DISABLED │
   └──────────┘
```

- **Warm-up** mirrors email-sending warm-up: a new IP starts with a low daily cap and ramps over days. New identities *never* get a firehose — that's exactly how the prototype's "list-size vs IP-age" incidents happened.
- **Quarantine** is automatic on strong negative signals (DNSBL listing, a burst of `5xx ...blocked` responses from a major provider) and includes a cool-down + re-audit before re-warming.
- A recovered identity **re-enters WARMING**, never jumps straight back to ACTIVE.

### 12.3 Health scoring inputs

Per identity, rolling window, **broken down per destination provider** (an IP can be fine for small corporate MX but burned for Gmail):

- acceptance ratio (250s) vs permanent failures (5xx *blocks*, distinct from 5xx *no-such-user*),
- tempfail/greylist ratio (4xx),
- connection refusals / timeouts (port-25 reachability, provider-level blocks),
- **DNSBL polling** (Spamhaus ZEN et al.) on a schedule,
- **PTR/rDNS audit** (forward-confirmed reverse DNS present and consistent — a Truemail-style host audit).

### 12.4 Routing policy (egress selection)

When the scheduler needs to probe `addr@destination`, it asks the reputation manager for the **best egress for *that destination provider***:

1. filter to `ACTIVE`/eligible `WARMING` identities with remaining daily cap,
2. exclude any with an **open circuit** for this destination provider,
3. exclude DNSBL-listed,
4. rank by per-provider health score, prefer ASN/region diversity, spread load,
5. return a binding; if none available → **defer** the task (`next_attempt_at`) rather than burn a marginal IP.

### 12.5 Per-(egress, destination) circuit breaker

A classic breaker keyed on the pair: consecutive blocks/tempfails from `destination` via `egress` → **open** (stop using that pair) for a cool-down → **half-open** trial → close on success. This localizes damage: one provider blocking one IP doesn't take the IP out of service for everyone else.

### 12.6 Per-destination rate limiting & greylist handling

- **Token-bucket per destination domain/MX** (Redis) — never hammer one server; respect its implied limits.
- **Greylisting is expected, not an error:** a 4xx tempfail schedules a retry via `next_attempt_at` with backoff, per the greylisting contract (retry after a delay from the *same* identity where possible).

### 12.7 Proxy providers as a plugin

`ProxyProvider` port supplies egress endpoints (static SOCKS5 list, a residential-proxy vendor API, a self-hosted proxy fleet). Residential proxies are supported but **off by default** and clearly flagged, because their legitimacy depends entirely on sourcing — the platform stays neutral infrastructure and documents the ethical/legal considerations rather than shipping a default that could be misused.

> **This section is why the project exists.** Reacher and email-verifier will happily run a probe; neither will tell you your Ashburn IP just got Spamhaus-listed, stop routing Gmail through it, quarantine it, and re-warm it next week. Vouch does.

---

## 13. Monitoring & Observability

**Reuse the standard stack; ship it configured.** Building custom monitoring for an infra project is a well-known anti-pattern.

- **Metrics — Prometheus.** Every binary exposes `/metrics`. First-class series:
  - `vouch_verifications_total{status,provider,engine,cached}`
  - `vouch_probe_duration_seconds` (histogram, by provider)
  - `vouch_egress_health{egress_id,provider}` and `vouch_egress_state{state}`
  - `vouch_egress_dnsbl_listed{list}`
  - `vouch_queue_depth{stream}`, `vouch_worker_inflight`
  - `vouch_cache_hits_total{cache}` / `..._misses_total`
  - `vouch_rate_limit_deferred_total{destination}`
- **Dashboards — Grafana.** Ship provisioned dashboards in `/deploy/grafana`: fleet throughput, acceptance-by-provider, **egress reputation board** (the money dashboard), queue depth & worker saturation, cache effectiveness.
- **Tracing — OpenTelemetry.** Trace a submission through funnel → schedule → probe → result. OTLP export to any collector.
- **Logging — structured JSON to stdout** (slog), correlation IDs propagated; Loki optional, never required.
- **Alerting — shipped Prometheus rules:** DNSBL listing on any active egress, acceptance-rate cliff for a provider, queue depth sustained above threshold, worker starvation, cert/port-25 reachability loss.
- **Health:** `/healthz` (liveness) and `/readyz` (dependencies reachable) on every binary.

The **egress reputation dashboard** turns the prototype's after-the-fact blacklist diagnosis into a leading indicator you watch in real time.

---

## 14. Security Model

- **AuthN:** API keys (hashed at rest, shown once, prefixed for identification) for programmatic access; **OIDC** for the admin UI (SSO-ready). No passwords stored by the app if OIDC is used.
- **AuthZ:** RBAC (`admin`, `operator`, `member`, `readonly`) + per-org scoping. API-key scopes limit blast radius (`verify:write`, `jobs:read`, `egress:admin`).
- **Multi-tenancy:** org-scoped rows everywhere; every query is tenant-filtered; job/result access checked against the caller's org.
- **Secrets:** 12-factor env by default; file-based secrets for Compose; **k8s Secrets / External-Secrets Operator** for k8s; optional **Vault** via a `SecretProvider` port. No secrets in the DB in plaintext; proxy credentials encrypted at rest (envelope encryption, key from the secret provider).
- **Transport:** TLS terminated at the ingress/reverse proxy; internal bus/DB traffic over TLS or a private network; webhook deliveries **HMAC-signed** so receivers can verify authenticity.
- **Input safety:** strict size/row caps on bulk uploads; SSRF guards on webhook targets and any user-supplied URL; DNS resolution sandboxed with timeouts.
- **Abuse posture:** Vouch is a *verification* tool, not a harvesting or spamming tool. Docs state the intended use plainly; the platform ships conservative rate defaults; residential proxies are opt-in and flagged; there is no bundled "scrape addresses" capability. This is both an ethics stance and a project-reputation safeguard.
- **Supply chain:** SBOM generated in CI (`syft`), dependency and container scanning (`govulncheck`, `trivy`), signed releases (`cosign`), pinned base images.
- **Data retention:** configurable TTLs; verified-address data is the customer's; a documented purge path for GDPR/DSR requests (relevant to EU self-hosters).

---

## 15. Scaling Strategy

**The load-bearing insight:** compute scales trivially; **trustworthy egress does not.** At every tier below, the constraint that actually changes is egress capacity + destination-side limits, and the biggest lever is the funnel + caches reducing *actual probe volume* far below input volume.

| Target | ~avg rate | Topology | Bus | Store | Egress reality |
|---|---|---|---|---|---|
| **100k/day** | ~1–2/s (bursty) | 1 VPS, Compose: `server` + 1–2 workers | Redis Streams | Postgres + Redis | A handful of clean IPs; funnel handles most of the list. This is the small-business default. |
| **1M/day** | ~12/s | 1 beefy node or 2–3 nodes | Redis Streams (or NATS) | + read replica; ClickHouse if analytics-heavy | Tens of egress identities across a couple of ASNs; warm-up discipline matters now. |
| **10M/day** | ~115/s | Kubernetes; workers on HPA | **NATS JetStream** | Postgres tuned + **ClickHouse** for analytics | Hundreds of identities across many ASNs/regions; regional worker placement; sharded rate limiters. |
| **100M/day** | ~1,150/s sustained | Multi-region k8s; sharded schedulers | NATS clustered | Postgres (Citus/sharded) + ClickHouse primary for reads | **This is a reputation & caching problem, not a throughput problem** — see below. |

### 15.1 What actually changes between tiers

- **100k → 1M:** add workers; add IPs with warm-up; maybe a Postgres read replica. Still one bus, still Compose-viable.
- **1M → 10M:** move to k8s; swap bus to **NATS JetStream**; HPA workers on `vouch_queue_depth`; introduce **ClickHouse** so analytics stops touching Postgres; shard the per-destination rate limiter (consistent-hash by destination domain). Place workers regionally so probes egress closer to destinations and across diverse ASNs.
- **10M → 100M:** the honest engineering answer — **you cannot open ~1.15k *new* SMTP probes/sec against real MX servers from a modest IP pool without getting nuked.** So the design at this tier leans on:
  - **Caching dominance** — result + catch-all + domain caches mean the *probe* rate is a fraction of the *input* rate. A mature deployment might probe only 10–30% of inputs.
  - **Provider skip/statistical** — the consumer-provider slice never probes at all.
  - **Massive egress diversity** — thousands of identities across many ASNs/regions/providers, each within safe per-identity caps; this is an *acquisition & reputation* problem, budgeted and warmed over weeks.
  - **Sharded control plane** — partition scheduler and reputation state by destination-domain hash; NATS clustered; ClickHouse as the analytical primary.

  **Challenge to the brief's framing:** "scale to 100M/day" implicitly reads as "add workers." The redesign's contribution is making it explicit that beyond ~10M/day, throughput is cheap and *reputation supply* is the wall. The platform's job is to squeeze probe volume down (funnel + caches) and route the remaining probes across a diverse, health-managed egress pool. Designing for "100M probes/day" naïvely would be designing to get every IP you own permanently blacklisted.

### 15.2 Scaling the control plane itself

- **Stateless API replicas** behind the LB; sticky only for SSE (or use a shared pub/sub for SSE fan-out).
- **Leader-elected singletons** (scheduler tick, reputation reconciler, retry-due scanner) via a Postgres advisory lock or k8s lease — active/standby, not a bottleneck at these volumes.
- **Hot state in Redis**, truth in Postgres; at the top tier, partition both by destination-domain hash.

---

## 16. Technology Stack

For each choice: the pick, why, and the runner-up.

| Concern | Choice | Why | Alternatives considered |
|---|---|---|---|
| **Control-plane + worker language** | **Go** | The ecosystem's lingua franca (k8s, Prometheus, Grafana, Harbor, Gitea, Listmonk); superb concurrency for network-bound probing; single static binary → self-host DX; the MIT default engine is already Go (link, don't shell out). | **Rust** (fastest, and Reacher's language — but smaller contributor pool, slower control-plane iteration; we still *use* Rust via the Reacher adapter). **Node/Python** (great DX, worse for high-concurrency network fan-out + single-binary distribution). |
| **Default engine** | **AfterShip email-verifier (MIT)** | Permissive → keeps core Apache-2.0 and the binary self-contained; in-process, no subprocess. | **Reacher (AGPL)** as opt-in out-of-process engine; **truemail-go**; native reimplementation (rejected — don't rebuild the engine). |
| **Bus** | **Redis Streams (default) / NATS JetStream (scale)** | Redis is already a dependency → zero-add default; JetStream is a lightweight, clustered, durable scale path. | **RabbitMQ** (solid but heavier; Reacher uses it — fine as a community adapter). **Kafka** (overkill for self-host). |
| **System of record** | **PostgreSQL** | Boring, transactional, universal, great tooling. | MySQL (fine, less rich); SQLite (great for tiny, but we need concurrent writers + the egress model). |
| **Analytics store** | **ClickHouse (optional, ≥10M/day)** | Column store built for append-heavy fact tables + fast aggregations. | TimescaleDB (nice, but ClickHouse wins at this shape/scale); "just use Postgres" (fine until it isn't). |
| **Cache / rate-limit / small-mode bus** | **Redis** | One tool for MX/catch-all/result caches, token buckets, hot egress state, and the default bus. | KeyDB/Dragonfly (drop-in, optional). |
| **Metrics / dashboards** | **Prometheus + Grafana** | The standard; ship provisioned dashboards. | VictoriaMetrics (compatible, optional). |
| **Tracing** | **OpenTelemetry (OTLP)** | Vendor-neutral; export anywhere. | Jaeger direct (via OTel). |
| **Logging** | **slog → JSON stdout (+ Loki optional)** | 12-factor; no hard dependency. | zap/zerolog (fine; stdlib slog keeps deps minimal). |
| **Auth** | **API keys + OIDC** | Keys for machines, OIDC for humans/SSO. | Built-in user/password (supported for airgapped, but OIDC preferred). |
| **Frontend** | **React + Vite SPA, embedded via `go:embed`** | Single-binary DX like Gitea/Listmonk; matches the team's existing React; TanStack Query + a small component kit. | Vue (Listmonk's choice — fine); Svelte (lean); HTMX+templ (great for simple admin, but the egress dashboards want a real SPA). |
| **Reverse proxy / ingress** | **Caddy (dev/simple) / nginx or Traefik / k8s Ingress** | Caddy = automatic TLS, trivial for self-host; Traefik/nginx for k8s. | — |
| **Secrets** | **env / file / k8s Secrets / External-Secrets / Vault (port)** | Meet self-hosters where they are; abstract it. | — |
| **Containerization / orchestration** | **Docker + Compose (small) / Helm chart + optional Operator (k8s)** | Compose for one box; Helm for fleets; Operator later for egress-pool CRDs. | Plain manifests (shipped too). |
| **CI/CD** | **GitHub Actions + goreleaser + release-please** | Native to the GitHub org; multi-arch builds, SBOM, signing, changelog automation. | — |

**License decision — Apache-2.0 for the core.** Permissive, enterprise-adoption-friendly, includes an explicit patent grant (better than MIT for a company-stewarded project seeking broad adoption; this is the k8s/Prometheus/Grafana lineage). **AGPL is deliberately avoided for the core** — it would scare off exactly the self-hosters and embedders we want. The AGPL-licensed Reacher engine is supported only as an **out-of-process, opt-in adapter**, keeping the copyleft obligation contained to that optional component. `LICENSING.md` documents this clearly and points commercial Reacher users to counsel.

---

## 17. Open-Source Repository Structure

Single **monorepo** under the TrySelfHost GitHub org. A monorepo (not many repos) because the API spec, server, worker, SDKs, deploy manifests, and docs must version together.

```
vouch/
├── cmd/
│   ├── vouch-server/         # control-plane binary
│   ├── vouch-worker/         # worker binary
│   └── vouch/                # CLI (verify, jobs, egress admin, migrate)
├── internal/                 # non-public application code (module boundaries)
│   ├── api/  ingestion/  pipeline/  scheduler/  egress/  policy/
│   ├── results/  identity/  observability/  admin/
│   └── platform/             # bus, store, cache, secrets adapters (ports live in each domain)
├── pkg/                      # public, importable libraries (stable API)
│   ├── engine/               # VerificationEngine port + builtin/reacher/mock adapters
│   └── verdict/              # public Verdict types shared with SDKs
├── api/
│   ├── openapi.yaml          # OpenAPI 3.1 — the contract (CI-gated)
│   └── proto/                # bus message + internal gRPC schemas
├── sdk/
│   ├── go/  ts/  python/     # generated clients (CI keeps them in sync)
├── web/                      # React+Vite SPA (embedded into vouch-server)
├── deploy/
│   ├── docker/               # Dockerfiles (multi-stage, distroless)
│   ├── compose/              # docker-compose.yml + profiles (small→scale)
│   ├── helm/                 # Helm chart
│   ├── k8s/                  # plain manifests
│   └── grafana/              # provisioned dashboards + Prometheus rules
├── migrations/               # forward-only SQL (goose/atlas)
├── test/
│   ├── integration/          # against real Postgres/Redis/NATS + smtpmock
│   ├── e2e/                  # full-stack scenarios
│   └── load/                 # k6/vegeta probe-throughput benches
├── docs/                     # Docusaurus/Astro site (Architecture, Ops, API, Contributing)
├── examples/                 # runnable snippets, terraform for a reference VPS deploy
├── .github/
│   ├── workflows/            # CI: lint, test, build, release, security, docs
│   ├── ISSUE_TEMPLATE/       # bug / feature / engine-adapter / security
│   └── PULL_REQUEST_TEMPLATE.md
├── CODEOWNERS
├── CONTRIBUTING.md  CODE_OF_CONDUCT.md  GOVERNANCE.md  SECURITY.md
├── LICENSE (Apache-2.0)  LICENSING.md (engine-license notes)  NOTICE
├── CHANGELOG.md (release-please)  ADR/ (architecture decision records)
└── README.md
```

**Coding standards:** `gofmt`+`goimports`, `golangci-lint` (curated linters) enforced in CI; `errcheck`; table-driven tests; `context.Context` first arg; ports in the domain package, adapters in `platform`/`pkg`. **ADRs** (`ADR/NNNN-title.md`) record every significant decision (this document seeds ADR-0001).

---

## 18. CI/CD Pipeline

GitHub Actions, fast and strict. A newcomer's PR gets full signal in minutes.

```
on PR:
  lint         → golangci-lint, gofmt check, openapi-lint, web (eslint/tsc)
  test         → unit (race detector on); integration (services via containers +
                 smtpmock); coverage gate
  contract     → openapi diff gate (fail on breaking change w/o version bump);
                 SDKs regenerated & verified in-sync
  build        → multi-arch (amd64/arm64) server+worker+cli; web bundle → go:embed
  security     → govulncheck, trivy (image + fs), gitleaks, syft SBOM
  docs         → build docs site; link-check

on merge to main:
  build+push edge images (ghcr.io); deploy docs (preview → prod)

on tag vX.Y.Z (release-please PR merged):
  goreleaser   → multi-arch binaries + images, checksums, cosign signatures,
                 SBOM attached; Helm chart packaged & published; CHANGELOG cut;
                 GitHub Release with notes
```

- **Branching:** trunk-based; short-lived feature branches; `main` always releasable. Optional `release/*` for backport/LTS once the project is mature.
- **Semantic versioning** driven by **Conventional Commits**; `release-please` computes the next version and assembles the changelog. Pre-1.0 while the API stabilizes; `v1.0.0` is the compatibility promise.
- **Every image multi-arch** (arm64 matters — lots of self-hosters run ARM VPSes/Pis).

---

## 19. Development Workflow

The five-minute onboarding is a hard requirement:

```bash
git clone github.com/tryselfhost/vouch && cd vouch
make dev        # brings up: server + 1 worker + postgres + redis + smtpmock
                # + seeds an org, api key, and a demo egress identity, all via
                # docker-compose with hot-reload (air) on the Go binaries and
                # Vite HMR on the web UI. Prints the local URL + api key.
make verify EMAIL=test@example.com   # hits the running stack end-to-end
```

- **Mock SMTP by default in dev:** `smtpmock` scripts deterministic server behaviours (250 accept, 550 no-such-user, 4xx greylist, catch-all, block) so probe logic is testable **without touching port 25 or real servers** — critical since most dev machines/ISPs block outbound 25 anyway.
- **Hot reload:** `air` for Go, Vite HMR for the SPA.
- **Testing tiers:** unit (fast, hermetic) → integration (real Postgres/Redis/NATS + smtpmock, via testcontainers) → e2e (full stack) → load (`k6`/`vegeta` against a mock-MX fleet to benchmark scheduler + worker throughput without harming anyone).
- **Debugging:** Delve-ready binaries; structured logs with correlation IDs; a `vouch debug egress` CLI to dump reputation state; OTel traces viewable in a local Jaeger from the dev compose profile.
- **Benchmarking:** `go test -bench` for hot paths (funnel, scheduler); a documented `test/load` harness so contributors can prove a change's throughput impact.
- **SDK generation:** `make sdk` regenerates Go/TS/Python clients from `openapi.yaml`; CI fails if they drift.
- **API docs:** rendered from OpenAPI (Redoc/Scalar) and published with the docs site.
- **First-issue friendliness:** `good-first-issue` labels, an `ADR` trail so newcomers understand *why*, and a `CONTRIBUTING.md` that explains the funnel/reputation model up front (the two things a contributor must grok).

---

## 20. Documentation Strategy

Docs are a first-class deliverable, versioned in-repo, built to a static site (Docusaurus or Astro Starlight). Structured by audience:

- **Get Started** — one-VPS Compose quickstart; "verify your first address in 5 minutes."
- **Concepts** — the funnel; the four-valued verdict; **egress & reputation** (the mental model that makes the product make sense); provider policies.
- **Operations** — deploying (Compose/Helm/k8s), scaling tiers, running an egress pool, warm-up guidance, reading the reputation dashboard, DNSBL response playbooks, backup/restore, upgrades.
- **API Reference** — generated from OpenAPI; SDK usage per language.
- **Extending** — writing an engine adapter, a proxy provider, a result sink; the plugin contracts.
- **Architecture** — this document (living), plus ADRs.
- **Contributing / Governance / Security** — how to participate and report.

Docs are CI-gated (build + link-check) and **change with the code in the same PR** — an API or behaviour change without a docs update fails review. A `docs/` change is a valid, celebrated first contribution.

---

## 21. Governance Model

Start pragmatic, with a clear path to community:

- **Early stage — BDFL-lite / lead-maintainer.** TrySelfHost holds maintainer authority to move fast and keep architectural coherence (esp. the reputation model). Transparent decision-making via ADRs and public issues.
- **Growth stage — maintainer council.** As external contributors earn trust, promote them to maintainers (documented ladder in `GOVERNANCE.md`); decisions by lazy consensus, escalate to a vote among maintainers when needed.
- **CODEOWNERS** enforce review by domain owners (egress, scheduler, API, engine adapters).
- **Contributions under DCO** (`Signed-off-by`), **not a CLA.** Rationale/trade-off: DCO is lighter and community-friendly (no legal gate to a first PR), which suits a self-host/OSS-first project; the cost is TrySelfHost cannot unilaterally relicense later. If a future need to relicense or dual-license is anticipated, a CLA would be required instead — a deliberate trade named here so it's a conscious choice, not a default. **Recommendation: DCO.**
- **RFC process** for large/breaking changes (an RFC template + discussion period before implementation).
- **Security policy** (`SECURITY.md`): private disclosure channel, response SLA, coordinated release.
- **Code of Conduct:** Contributor Covenant.
- **Release cadence:** time-boxed minors (e.g., monthly) + patches as needed; a documented support window once v1 lands.

Neutral-infrastructure posture in docs (verification, not harvesting/spam) is part of governance — it protects the project's standing in the broader mail community.

---

## 22. Roadmap

Prioritized by impact. The ordering reflects the thesis: **reputation management is what makes this worth building**, so it appears early, not "later."

### MVP (prove the platform is real)
- Two binaries (`server`, `worker`) + Compose; Postgres + Redis; Redis Streams bus.
- Ingestion (single + bulk CSV), Jobs/Tasks, dedup.
- **The funnel** (syntax → normalize → cache → MX → disposable/role/free → catch-all).
- **builtin engine** (email-verifier, MIT), in-process.
- Scheduler with **per-destination rate limiting** + greylist-aware retry.
- **Egress manager v1**: identity pool, health scoring, quarantine, warm-up, DNSBL polling, routing. *(Non-negotiable — it's the point.)*
- Provider-policy engine with sane consumer-provider defaults (probe/skip).
- REST API (OpenAPI), API-key auth, webhooks, result cache.
- Prometheus metrics + one shipped Grafana dashboard; structured logs; health endpoints.
- Mock-SMTP dev stack; unit + integration tests; `make dev` in 5 minutes.

### v1 (production-ready release)
- **NATS JetStream** bus adapter; Kubernetes **Helm chart**; HPA guidance.
- **Reacher engine adapter** (AGPL, out-of-process) — engine choice per policy.
- Provider policy **statistical** strategy; hot-reload; admin UI editing.
- **Embedded React admin UI**: job monitoring, the **egress reputation dashboard**, policy editor.
- OIDC auth + RBAC + multi-tenant hardening.
- Circuit breakers per (egress, destination); PTR/rDNS host audits.
- ClickHouse analytics sink (optional); SSE live progress; streaming CSV export.
- Generated Go/TS/Python SDKs; full docs site; signed multi-arch releases + SBOM.
- Backup/restore + upgrade playbooks; shipped alert rules.

### v2.x and beyond (future roadmap)
- **Kubernetes Operator** with CRDs for egress pools (declarative reputation infra).
- **Statistical/ML confidence** models per provider trained on historical acceptance.
- **Provider-API engine adapters** (postmaster/feedback signals where available).
- Sharded/partitioned control plane for the 100M/day tier (Citus, clustered NATS).
- Pluggable **result sinks** (Kafka, S3/parquet, warehouse connectors).
- **Marketplace** of community engine/policy/proxy plugins.
- Deliverability adjacencies (SPF/DKIM/DMARC/MX health reporting for a domain).
- Federated/regional deployments with a shared reputation ledger.

---

## 23. Risks & Trade-offs

| Risk | Severity | Mitigation |
|---|---|---|
| **Reacher AGPL taint** if ever linked in-process | High (legal) | Reacher is **out-of-process, opt-in only**; default engine is MIT; `LICENSING.md` + arm's-length interface; recommend counsel for commercial Reacher. |
| **Ethical/abuse concern** — verification tooling can enable spam/harvesting | High (reputation) | No harvesting features; conservative defaults; residential proxies opt-in + flagged; clear intended-use docs; neutral-infra governance posture. |
| **Consumer-provider unreliability makes results look "wrong"** | Medium | Four-valued honest verdicts + `sub_status`; provider skip/statistical policy; docs set expectations explicitly. This is a *feature* (honesty), framed as such. |
| **Egress model is the hard part; getting it wrong burns IPs** | High | It's the earliest, best-tested subsystem; warm-up defaults conservative; extensive integration tests with smtpmock block/greylist scenarios; the reputation dashboard makes failure visible early. |
| **Scope creep toward "do everything"** | Medium | Ruthless MVP; plugins push non-core features out of the core; ADRs gate additions. |
| **Solo/small maintainer bandwidth** (esp. alongside other commitments) | Medium | Monorepo + heavy CI automation (release-please/goreleaser) minimize release toil; DCO lowers contributor friction; docs-with-code keeps knowledge externalized. |
| **Self-host DX regressions** as complexity grows | Medium | `make dev` 5-minute check is a CI-enforced smoke test; Compose profiles keep the small path trivial. |
| **Bus/store abstraction leaks** | Low–Med | Conformance test suites every adapter must pass; ports kept narrow. |
| **Over-engineering (CQRS/microservices temptation)** | Low–Med | Explicitly deferred in §5.2; adopt only on a real scaling signal. |

**Honest meta-trade-off:** this design optimizes for *long-term maintainability and operational excellence over initial simplicity*, exactly as requested — which means the MVP is heavier than a "wrap Reacher in an API" weekend build. The justification is that the *simple* version already exists (the prototype) and its ceiling is the unmanaged-reputation problem. Paying the design cost now is what turns a useful internal tool into a reference-quality OSS platform.

---

## 24. Migration Plan from the Current Prototype

**Strangler-fig, zero-downtime.** Keep the working Reacher-worker prototype serving traffic while Vouch grows around it, then cut over.

```
Phase 0 — Wrap (no user-visible change)
  · Introduce the message bus (Redis Streams) between the existing API and the
    existing Reacher workers.
  · Wrap current Reacher workers behind the `VerificationEngine` port as the
    `reacher` adapter (out-of-process). Nothing else changes yet.
  · Add Prometheus /metrics + structured logs to gain visibility immediately.

Phase 1 — Control plane in parallel
  · Stand up vouch-server alongside the old API. Implement the FUNNEL and
    RESULT/DOMAIN caches first — instant probe-volume (reputation) savings with
    zero risk, since survivors still go to existing workers.
  · Stand up the EGRESS/REPUTATION manager in "observe" mode: it ingests
    egress.signals and scores health but doesn't yet gate routing. Watch the
    dashboard vs. reality to build trust.

Phase 2 — Cut over ingestion + routing
  · Point the frontend/clients at vouch-server's /v1 API (old endpoints proxied
    for back-compat during transition).
  · Flip the egress manager to "enforce": it now selects egress + rate-limits +
    quarantines. Reacher remains the engine (via adapter) — de-risks by changing
    orchestration without changing the probe logic.

Phase 3 — Engine + UI modernization
  · Introduce the builtin (MIT) engine; run it shadow/side-by-side with Reacher
    on a sample to compare verdicts; shift default per provider policy where the
    builtin matches or wins. Reacher stays available as opt-in.
  · Migrate the custom frontend to the embedded React admin UI (or point it at
    the new API). Decommission the old dispatcher-in-frontend logic (P1).

Phase 4 — Decommission
  · Retire the old API/frontend paths once traffic is fully on /v1.
  · Old Reacher workers now run only via the engine adapter, scaled by the new
    scheduler.
```

**Migration safety rails:** shadow-compare verdicts before switching defaults; egress manager runs in observe-then-enforce; caches added first (pure upside); every phase independently reversible via config flags. Because the client deployment (`nyelizabeth.net` / production lists) has real users, Phases 0–2 change *orchestration around* the unchanged probe engine, and only Phase 3 touches the engine itself — behind a shadow comparison.

---

## 25. Future Enhancements

Beyond the roadmap's v2, longer-horizon ideas worth an ADR when their time comes:

- **Shared reputation intelligence** (opt-in, privacy-preserving) — aggregate anonymized egress-health signals across cooperating self-hosted instances into a community DNSBL-like feed, so a burned range known to one deployment warns others. Federated, opt-in, no address data shared — only egress/destination-class reputation.
- **Deliverability suite** — extend from "does this address exist" to "is this domain healthy to send from": SPF/DKIM/DMARC/BIMI/MX/TLS-RPT reporting. Natural adjacency for TrySelfHost's mail-infra work.
- **Adaptive warm-up** — learn per-ASN/per-provider warm-up curves from observed acceptance rather than fixed schedules.
- **Cost-aware routing** — when residential/paid proxies are in the pool, route by (reputation × cost) to minimize spend per confident verdict.
- **WASM policy plugins** — let operators write provider policies in any language, sandboxed, hot-loaded.
- **Verdict explainability API** — full decision trace for a verdict (which stage, which egress, which signals) for auditability and support.

---

### Appendix A — Ubiquitous language (glossary)

- **Job** — a submitted batch (or single) verification request.
- **Task** — one address's verification within a job; carries retry/greylist scheduling.
- **Verdict** — the four-valued result (`deliverable | undeliverable | risky | unknown`) + reason code + checks.
- **Engine** — the pluggable component that performs the SMTP-level check (builtin/reacher/…).
- **Funnel** — the cheap-to-expensive pipeline that eliminates addresses before probing.
- **Egress identity** — an (IP, rDNS/PTR, HELO, optional proxy) tuple used to probe.
- **Reputation manager** — the subsystem that scores, warms, quarantines, and routes egress identities.
- **Provider policy** — declarative strategy (probe/skip/statistical/api) per destination provider.
- **Catch-all** — a domain whose MX accepts any local-part; per-mailbox SMTP verification is impossible.

### Appendix B — Key decisions at a glance (ADR seeds)

1. Modular monolith control plane + stateless worker fleet (not microservices).
2. Go for both binaries; MIT engine linked as default.
3. Engine is a plugin; Reacher (AGPL) supported out-of-process only.
4. Bus is a port: Redis Streams default, NATS JetStream at scale.
5. Postgres system-of-record; ClickHouse optional analytics ≥10M/day.
6. Reputation management is a first-class, early subsystem — the differentiator.
7. Four-valued honest verdict; provider policy encodes consumer-provider reality.
8. Apache-2.0 core; DCO contributions.
9. Prometheus/Grafana/OTel reused, not rebuilt.
10. Scale beyond ~10M/day is a reputation+caching problem, not a throughput one.

*End of proposal.*
