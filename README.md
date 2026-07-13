# rcpttō

**Self-hosted SMTP email verification platform.** Engine-agnostic, reputation-aware, and built to run on one VPS or a Kubernetes fleet.

> Named for the SMTP `RCPT TO` command — the moment a mail server actually tells you whether a mailbox exists.
> Stewarded by [TrySelfHost](https://tryselfhost.com). Licensed under **Apache-2.0**.

---

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

Coming next (in priority order): **persistence + the `/v1` API** (submit, job status, results), then wiring the funnel and engine together behind it. See the [roadmap](docs/DESIGN.md#22-roadmap).

## Why another verifier?

Good verification *engines* already exist (Reacher, AfterShip's email-verifier). What's missing is a self-hostable *platform* around them that solves the things that actually determine accuracy at scale — chiefly **egress reputation management**. Accuracy is a reputation problem, not a code problem: the moment a probing IP is flagged, results degrade sharply, and no OSS project manages that lifecycle. rcpttō does. The full rationale is in [`docs/DESIGN.md`](docs/DESIGN.md).

Two principles worth knowing up front:

- **Honest `unknown`.** We never dress up an unreliable result as a verdict. A Gmail address we can't reliably probe is `risky`/`unknown` with a reason code — not a fake `invalid`.
- **Engine-agnostic.** The verification engine is a plugin. The default is permissively licensed and linked in-process; heavier or copyleft engines are opt-in adapters.

## Requirements

- **Go 1.26+** (the module currently declares `go 1.22` only so it builds in a constrained CI sandbox — bump it to `1.26` locally; the code is plain standard library).

## Getting started (contributors)

```bash
git clone https://github.com/tryselfhost/rcptto
cd rcptto

make test    # race-enabled unit tests
make check   # fmt + vet + test — the local pre-commit gate
make help    # list all targets
```

There is nothing to *run* yet — the buildable surface is the library packages above. A `make dev` full-stack target (server + worker + Postgres + Redis + mock SMTP) arrives with the API milestone.

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
