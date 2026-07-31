# Dependency notes

## `go.sum` / vendoring

This repository vendors its dependencies (`vendor/`, committed to git). `go
build`, `go vet`, and `go test` all auto-detect `vendor/` and use it — no
network access to any module proxy is required to build this project, on any
machine. This was a deliberate choice after intermittent DNS/network issues
made `proxy.golang.org` unreachable from some environments; vendoring removes
that dependency entirely.

If you add or update a dependency:

```bash
go get <module>@<version>
go mod tidy
go mod vendor
git add go.mod go.sum vendor
```

## `replace` directives in `go.mod`

A few transitive dependencies (test-only or otherwise) are pulled in via
`gopkg.in/*` and `golang.org/x/*` import paths. Both hostnames resolve through
a Go-specific meta-redirect mechanism that some restricted-network build
environments cannot reach even when the underlying code is plain GitHub. To
keep this project buildable from environments with a locked-down egress
allowlist, `go.mod` replaces these with their canonical GitHub mirrors:

| Import path | Replaced with |
|---|---|
| `gopkg.in/yaml.v3` | `github.com/go-yaml/yaml` |
| `gopkg.in/check.v1` | `github.com/go-check/check` |
| `golang.org/x/crypto` | `github.com/golang/crypto` |
| `golang.org/x/text` | `github.com/golang/text` |
| `golang.org/x/sync` | `github.com/golang/sync` |

These are the same upstream source, mirrored 1:1 — the `replace` directives
only change *where the source is fetched from*, not what code is compiled.
`yaml.v3` and `check.v1` are pulled in only as test-only transitive
dependencies of `pgx`'s own dependency graph; they are not imported by this
project's code.

If a network environment can reach `proxy.golang.org` and `golang.org`/`gopkg.in`
directly, these `replace` lines are not required — they are a compatibility
accommodation, not a correctness requirement. They can be removed with `go mod
edit -dropreplace=<path>` followed by `go mod tidy` on such an environment.
