# Upgrading dependencies

## Current state

| Module | Pinned | Fully patched | Why not on the latest |
|---|---|---|---|
| `github.com/jackc/pgx/v5` | v5.8.0 | v5.10.0 | v5.10.0 requires Go 1.25 |
| `github.com/xuri/excelize/v2` | v2.10.0 | v2.11.0 | v2.11.0 requires Go 1.25 |

`go.mod` targets **Go 1.24**, so the pins above are the newest versions that
build on it.

## Recommended: move to the fully patched versions

If your toolchain is Go 1.25 or newer (check with `go version`), upgrade:

```bash
go mod edit -go=1.25.0
go get github.com/jackc/pgx/v5@v5.10.0
go get github.com/xuri/excelize/v2@v2.11.0
go mod tidy
go mod vendor

go build ./... && go test ./...
```

Then raise the CI toolchain to match, in `.github/workflows/ci.yml`:

```yaml
go-version: '1.25'
```

## What the outstanding advisories actually cover

**pgx** — the v5.10.0 release hardens the driver against a *malicious or
compromised PostgreSQL server*: bounded binary decoders, a cap on
server-supplied SCRAM iteration counts, `require_auth` to prevent
authentication downgrade under `sslmode=prefer`, and TLS for cancellation
requests. In a self-hosted deployment where you own the database, that threat
model barely applies — but there is no reason to carry it once your toolchain
allows the upgrade.

**excelize** — an unbounded row-index allocation in the worksheet parser, which
a crafted `.xlsx` can use to exhaust memory. This one is directly reachable:
`internal/ingest` parses uploaded spreadsheets. Exposure is limited to
authenticated dashboard users (uploads sit behind the dashboard login), and
uploads are capped at 32 MiB, but a client-supplied sheet is still attacker
-influenced input. **Prioritize this upgrade if you process sheets you did not
create.**

## Why dependencies are vendored

`vendor/` is committed, so builds need no module proxy. After any dependency
change, re-run `go mod vendor` and commit the result, or the build will fail
with an inconsistent-vendoring error. See
[`DEPENDENCIES.md`](DEPENDENCIES.md) for the `replace` directives and the
reasoning behind vendoring.
