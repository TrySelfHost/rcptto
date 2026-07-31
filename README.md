# rcpttō

**Self-hosted SMTP email verification platform.** Engine-agnostic, reputation-aware, and built to run on one VPS or a Kubernetes fleet.

> Named for the SMTP `RCPT TO` command — the moment a mail server actually tells you whether a mailbox exists.
> Stewarded by [TrySelfHost](https://tryselfhost.com). Licensed under **Apache-2.0**.

---

## Deployment scope (current)

This build targets **a single VPS with Docker Compose** — not Kubernetes. The
`internal/jobs` worker pool runs in-process, egress defaults to one identity
(the host's own IP), and Postgres is a single instance. That's the right shape
for TrySelfHost's actual scale today.

Kubernetes, Helm charts, NATS/JetStream, and ClickHouse are described in the
[design doc](docs/DESIGN.md) as the path for high-volume, multi-node
deployments (§15), but are **not** part of the current roadmap — they add
real operational cost with no benefit below roughly 10M verifications/day.
Revisit only if that scale becomes a real requirement.

## Status

🚧 **Early development.** This repository is being built up module by module from the [architecture proposal](docs/DESIGN.md). It is **not yet runnable end-to-end.**

What exists today:

| Package | Purpose | State |
|---|---|---|
| [`pkg/verdict`](pkg/verdict) | The stable, public four-valued result type (`deliverable`/`undeliverable`/`risky`/`unknown`) + reason codes. | ✅ implemented + tested |
| [`pkg/engine`](pkg/engine) | The pluggable `VerificationEngine` port and supporting types (`Task`, `EgressBinding`, `Signal`, `Caps`). | ✅ interface defined |
| [`pkg/engine/mock`](pkg/engine/mock) | Deterministic mock engine + test egress binding — lets the rest of the codebase be tested without real mail servers or port 25. | ✅ implemented + tested |
| [`internal/pipeline`](internal/pipeline) | The verification funnel: syntax → normalize → disposable → role → free → MX. Returns a terminal verdict or a "needs-probe" task. Cheap, in-memory checks run before the one network-bound (DNS) stage. | ✅ implemented + tested |
| [`pkg/engine/builtin`](pkg/engine/builtin) | The default SMTP engine (the probe stage): native `net/textproto` client, MX failover, catch-all detection, and careful classification of mailbox-not-found vs. policy-block vs. greylisting. MIT/Apache-clean, linked in-process. | ✅ implemented + tested |
| [`internal/store`](internal/store) + [`memory`](internal/store/memory) | Persistence ports (`ResultStore`, `JobStore`) with in-memory adapters — the zero-dependency default. | ✅ implemented + tested |
| [`internal/store/postgres`](internal/store/postgres) | Durable Postgres adapters behind the same ports, with an embedded, self-applying migration runner. Pure `database/sql` (driver chosen in `main`). | ✅ implemented + CI integration-tested |
| [`internal/verifier`](internal/verifier) | Composition root: runs the funnel, probes survivors through an egress identity, applies the result cache, and merges funnel + SMTP findings. Includes the `EgressProvider` seam for the future reputation manager. | ✅ implemented + tested |
| [`internal/api`](internal/api) + [`cmd/rcptto-server`](cmd/rcptto-server) | HTTP API (`POST /v1/verify`, bulk `/v1/jobs`, `/healthz`, `/readyz`) with API-key auth and RFC 7807 errors, plus the runnable server binary. | ✅ implemented + tested |
| [`internal/jobs`](internal/jobs) | Async bulk runner: dedups a batch, processes addresses through a bounded worker pool, records verdicts, and supports cancellation. In-process MVP; a durable bus (Redis/NATS) splits workers out later. | ✅ implemented + tested |
| [`internal/egress`](internal/egress) | **The reputation manager** — the platform's differentiator. Health-scores each egress identity per destination, trips per-(identity,destination) circuit breakers, quarantines on block streaks, ramps warm-up daily caps, and routes each probe to the healthiest eligible identity. Implements the `EgressProvider` + `SignalSink` seams, closing the reputation feedback loop. | ✅ implemented + tested |
| [`internal/policy`](internal/policy) | Provider-policy engine — the honesty layer. Declarative probe/skip rules per destination provider, with sane defaults (Gmail/Yahoo/Microsoft/365 → skip, since probing them is unreliable and burns reputation for no signal). A skip never reaches the engine; the verdict is an honest `risky/provider_skipped`. | ✅ implemented + tested |
| [`internal/egress/audit`](internal/egress/audit) | Proactive reputation audits: DNSBL (blocklist) checks that quarantine a listed IP before probes start failing, and PTR/FCrDNS reverse-DNS verification. Injectable resolver; the server runs DNSBL audits on a schedule when `RCPTTO_DNSBL_ZONES` is set. | ✅ implemented + tested |
| [`internal/api/admin.go`](internal/api/admin.go) | Admin API — `GET /v1/admin/egress`, quarantine/enable/disable per identity, `GET/PUT /v1/admin/policies` — so the reputation system is inspectable and operable at runtime, not just at startup. Behind the same API-key auth as the rest of `/v1`. | ✅ implemented + tested |

| [`internal/web`](internal/web) | The dashboard — server-rendered HTML + htmx, embedded via `go:embed` (no Node build step, still one binary). Verify form, bulk submission, live job progress, and operable egress/policy screens. | ✅ implemented + tested |

Coming next: persisting egress reputation state across restarts (warm-up
progress and quarantine currently reset on restart), wiring PTR/FCrDNS audit
results into the reputation score, and multi-IP egress pool support. Kubernetes/Helm/NATS/ClickHouse are intentionally out of scope for now — see [Deployment scope](#deployment-scope-current) above. Full roadmap in [`docs/DESIGN.md`](docs/DESIGN.md#22-roadmap).

## Why another verifier?

Good verification *engines* already exist (Reacher, AfterShip's email-verifier). What's missing is a self-hostable *platform* around them that solves the things that actually determine accuracy at scale — chiefly **egress reputation management**. Accuracy is a reputation problem, not a code problem: the moment a probing IP is flagged, results degrade sharply, and no OSS project manages that lifecycle. rcpttō does. The full rationale is in [`docs/DESIGN.md`](docs/DESIGN.md).

Two principles worth knowing up front:

- **Honest `unknown`.** We never dress up an unreliable result as a verdict. A Gmail address we can't reliably probe is `risky`/`unknown` with a reason code — not a fake `invalid`.
- **Engine-agnostic.** The verification engine is a plugin. The default is permissively licensed and linked in-process; heavier or copyleft engines are opt-in adapters.

## Requirements

- **Go 1.22+** (the module targets `go 1.22` for broad toolchain compatibility; a newer installed Go, e.g. 1.26, builds it without any changes).

## Getting started (contributors)

```bash
git clone https://github.com/tryselfhost/rcptto
cd rcptto

make test    # race-enabled unit tests
make check   # fmt + vet + test — the local pre-commit gate
make help    # list all targets
```

### Run the server

```bash
go run ./cmd/rcptto-server        # listens on :8080 by default
```

Then open **<http://localhost:8080/>** for the dashboard: verify a single
address, submit a bulk job and watch it progress live, inspect and control
egress identities (quarantine / enable / disable), and edit provider policy —
all server-rendered with htmx, embedded in the binary. Set
`RCPTTO_DASHBOARD=false` to serve the JSON API only.

The same functionality is available over the JSON API:

```bash
# in another shell:
curl -s localhost:8080/healthz
curl -s -X POST localhost:8080/v1/verify \
  -H 'Content-Type: application/json' \
  -d '{"email":"someone@example.com"}'

# bulk: submit a job, then poll status and fetch results
JOB=$(curl -s -X POST localhost:8080/v1/jobs \
  -H 'Content-Type: application/json' \
  -d '{"emails":["a@example.com","b@example.com"]}' | jq -r .id)
curl -s localhost:8080/v1/jobs/$JOB
curl -s "localhost:8080/v1/jobs/$JOB/results?limit=100"

# admin: inspect and control egress identities and provider policy
curl -s localhost:8080/v1/admin/egress
curl -s -X POST localhost:8080/v1/admin/egress/direct/quarantine \
  -d '{"reason":"manual test"}'
curl -s -X POST localhost:8080/v1/admin/egress/direct/enable
curl -s localhost:8080/v1/admin/policies
curl -s -X PUT localhost:8080/v1/admin/policies/gmail \
  -d '{"strategy":"probe","reason":"testing on a clean IP"}'
```

### Configuration

| Variable | Default | Purpose |
|---|---|---|
| `RCPTTO_ADDR` | `:8080` | Listen address. Use `127.0.0.1:8080` behind a proxy. |
| `RCPTTO_HELO` | `localhost` | EHLO/HELO name. **Must** be a real hostname with matching forward + reverse DNS. |
| `RCPTTO_MAIL_FROM` | `verify@localhost` | Envelope sender used in probes. |
| `RCPTTO_API_KEYS` | *(empty)* | Comma-separated; when set, `/v1/*` requires an `X-API-Key` header. |
| `RCPTTO_DASHBOARD` | `true` | Set `false` to serve the JSON API only. |
| `RCPTTO_DASHBOARD_USER` | *(empty)* | Dashboard username. Must be set together with the password. |
| `RCPTTO_DASHBOARD_PASSWORD` | *(empty)* | Dashboard password. **Without these the dashboard is unauthenticated.** |
| `RCPTTO_SESSION_SECRET` | *(random)* | Signs dashboard session cookies. Set it so restarts don't log everyone out. |
| `RCPTTO_SECURE_COOKIE` | `false` | Set `true` once TLS terminates in front of the server. |
| `RCPTTO_DETECT_CATCHALL` | `true` | Probe a random local-part to detect catch-all domains. |
| `RCPTTO_DNSBL_ZONES` | *(empty)* | Comma-separated DNSBL zones (e.g. `zen.spamhaus.org`). Egress IPs are audited every 15 min; listed IPs are quarantined. |
| `DATABASE_URL` | *(empty)* | Postgres DSN. Falls back to in-memory storage when unset. |

> **Dashboard security.** The dashboard can quarantine egress identities and
> rewrite provider policy — treat it as admin access. Set
> `RCPTTO_DASHBOARD_USER`/`RCPTTO_DASHBOARD_PASSWORD` before it is reachable by
> anything other than you on localhost. The server logs a warning at startup
> when it is left unprotected.
>
> Public DNSBLs like Spamhaus refuse queries from shared/public resolvers — use
> your own resolver or a proper data feed in production.

## Deploying

See **[`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md)** for the full guide: DNS/PTR
setup (the single highest-impact step for deliverability), Docker Compose and
systemd deployment, reverse proxy + TLS, a security checklist, backups, and
first-run guidance.

```bash
cp deploy/compose/.env.example deploy/compose/.env   # fill it in
docker compose -f deploy/compose/docker-compose.yml \
               --env-file deploy/compose/.env up -d --build
```

### Persistence (Postgres)

By default the server keeps results and jobs in memory (lost on restart). Set
`DATABASE_URL` to use Postgres instead — the server applies the embedded
migrations on startup automatically:

```bash
docker compose -f deploy/compose/docker-compose.postgres.yml up -d
export DATABASE_URL='postgres://rcptto:rcptto@localhost:5432/rcptto?sslmode=disable'
go run ./cmd/rcptto-server        # now durable; auto-migrates on boot
```

The Postgres adapters live in `internal/store/postgres` and implement the same
`ResultStore`/`JobStore` ports as the in-memory ones — nothing else in the
codebase changes. The SQL driver (`pgx`) is already vendored (see
[`docs/DEPENDENCIES.md`](docs/DEPENDENCIES.md)), so no `go mod tidy` or network
access is needed to build with Postgres support. Integration tests run
against a real database:

```bash
go test -tags=integration ./internal/store/postgres/...   # needs DATABASE_URL
```

> **Note on port 25:** live SMTP verification requires outbound port 25, which
> most residential ISPs and cloud providers block by default. On such a host the
> probe stage will report `unknown`/`no_connect` — the funnel (syntax, MX,
> disposable, role) still works. Run somewhere with port 25 egress for full
> verification.

## Repository layout (target)

```
pkg/            public, importable contracts (verdict, engine + adapters)
internal/       application modules (api, ingestion, pipeline, scheduler,
                egress, policy, results, identity, observability)   — upcoming
cmd/            binaries: rcptto-server, rcptto-worker, rcptto (CLI)  — upcoming
api/            OpenAPI spec + bus/proto schemas                       — upcoming
deploy/         compose, helm, k8s, grafana dashboards                 — upcoming
docs/           DESIGN.md (architecture) + docs site                   — DESIGN.md present
```

## Contributing

Contributions are under the **DCO** (`Signed-off-by`), not a CLA. See `CONTRIBUTING.md` (upcoming) and the [governance model](docs/DESIGN.md#21-governance-model). The two concepts every contributor should understand first are the **funnel** (cheap-to-expensive checks that protect reputation) and the **egress reputation model** — both are described in the design doc.

## License

Apache-2.0 — see [`LICENSE`](LICENSE). The optional Reacher engine adapter is AGPL-3.0 and kept strictly out-of-process; see `LICENSING.md` (upcoming) before enabling it commercially.
