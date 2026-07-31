# Deploying rcpttō

This guide covers a single-VPS deployment — the shape rcpttō is designed for.
Kubernetes and multi-node topologies are out of scope (see the README's
*Deployment scope* section).

---

## 1. Before anything else: DNS hygiene

**This matters more than any other step on this page.** SMTP verification
opens connections to other people's mail servers. Those servers judge you
almost entirely on the identity you present, and the two things they check
first are your HELO name and your reverse DNS.

A server presenting `HELO localhost` from an IP with no matching PTR record
looks exactly like a spam host, and will start collecting blocks regardless of
how low your volume is.

### Set it up

1. **Pick a hostname** for the verifier, e.g. `verify.example.com`.

2. **Forward DNS**: create an `A` record pointing that hostname at your
   server's public IPv4 address.

   ```
   verify.example.com.  A  203.0.113.10
   ```

3. **Reverse DNS (PTR)**: set the PTR record for `203.0.113.10` to
   `verify.example.com`. This is done in your **VPS provider's control panel**,
   not your DNS host — Hetzner Cloud, OVH, and most others expose it directly
   on the server or IP settings page.

4. **Verify both directions match** (forward-confirmed reverse DNS):

   ```bash
   dig +short verify.example.com          # → 203.0.113.10
   dig +short -x 203.0.113.10             # → verify.example.com.
   ```

   Both must agree. rcpttō can audit this for you once running — see
   `internal/egress/audit`.

5. **Set `RCPTTO_HELO=verify.example.com`** in your configuration.

### Confirm outbound port 25 is open

Most cloud providers block outbound TCP/25 by default; some (Azure, Oracle,
GCP) block it permanently. Hetzner and OVH generally allow it, sometimes after
a support request.

```bash
# Should connect, not hang or refuse:
timeout 10 bash -c 'cat < /dev/null > /dev/tcp/gmail-smtp-in.l.google.com/25' \
  && echo "port 25 open" || echo "port 25 BLOCKED"
```

If it's blocked, the funnel (syntax, MX, disposable, role, policy) still works,
but SMTP probes return `unknown`/`no_connect`.

---

## 2. Option A — Docker Compose (recommended)

```bash
git clone https://github.com/tryselfhost/rcptto
cd rcptto

cp deploy/compose/.env.example deploy/compose/.env
$EDITOR deploy/compose/.env        # fill in every blank; see comments in the file

docker compose -f deploy/compose/docker-compose.yml \
               --env-file deploy/compose/.env up -d --build
```

Generate the secrets it asks for:

```bash
openssl rand -base64 24   # POSTGRES_PASSWORD
openssl rand -base64 24   # RCPTTO_DASHBOARD_PASSWORD
openssl rand -base64 32   # RCPTTO_SESSION_SECRET
```

The server **binds to `127.0.0.1:8080` by default**, so the dashboard is not
reachable from the internet until you deliberately put a proxy in front of it
(step 4). Check it locally:

```bash
curl -s localhost:8080/healthz
```

Dependencies are vendored, so the Docker build needs no module proxy and works
on a machine with restricted network egress.

---

## 3. Option B — systemd (no Docker)

Build the binary (on the server, or cross-compile and copy it over):

```bash
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o rcptto-server ./cmd/rcptto-server
```

Install it as a hardened service:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin rcptto
sudo install -m 0755 rcptto-server /usr/local/bin/rcptto-server
sudo install -d -o rcptto -g rcptto /etc/rcptto
```

Create `/etc/rcptto/rcptto.env` (mode `0640`, owner `root:rcptto` — it holds
credentials):

```ini
RCPTTO_ADDR=127.0.0.1:8080
DATABASE_URL=postgres://rcptto:PASSWORD@localhost:5432/rcptto?sslmode=disable
RCPTTO_HELO=verify.example.com
RCPTTO_MAIL_FROM=verify@example.com
RCPTTO_DASHBOARD_USER=admin
RCPTTO_DASHBOARD_PASSWORD=CHANGEME
RCPTTO_SESSION_SECRET=CHANGEME
RCPTTO_SECURE_COOKIE=true
```

```bash
sudo install -m 0640 -o root -g rcptto /etc/rcptto/rcptto.env /etc/rcptto/rcptto.env
sudo install -m 0644 deploy/systemd/rcptto.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now rcptto
journalctl -u rcptto -f
```

The unit runs unprivileged with a strict sandbox (read-only filesystem, no new
privileges, syscall filtering) — see `deploy/systemd/rcptto.service`.

---

## 4. Reverse proxy + TLS

Never expose the dashboard over plain HTTP. Caddy is the least-effort option
since it obtains and renews certificates automatically:

```caddyfile
verify.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Then set `RCPTTO_SECURE_COOKIE=true` so session cookies are HTTPS-only, and
restart the server.

**Defense in depth:** the dashboard has its own login, but if only you need
access, also restrict by source IP at the proxy:

```caddyfile
verify.example.com {
    @notme not remote_ip 203.0.113.99
    respond @notme 403
    reverse_proxy 127.0.0.1:8080
}
```

---

## 5. Security checklist

Work through this before pointing real traffic at it:

- [ ] `RCPTTO_HELO` set to a real hostname; forward and reverse DNS agree
- [ ] Outbound port 25 confirmed open
- [ ] `RCPTTO_DASHBOARD_USER` / `RCPTTO_DASHBOARD_PASSWORD` set (the dashboard
      can quarantine egress identities and rewrite provider policy — treat it
      as admin access)
- [ ] `RCPTTO_SESSION_SECRET` set, so restarts don't invalidate all sessions
- [ ] `RCPTTO_SECURE_COOKIE=true` once TLS is in front
- [ ] `RCPTTO_API_KEYS` set if `/v1/*` is reachable off-host
- [ ] Server bound to `127.0.0.1`, with a reverse proxy terminating TLS
- [ ] Postgres **not** exposed publicly (the bundled compose file doesn't
      publish its port)
- [ ] Database backups scheduled (see below)

---

## 6. Backups

Verification results are reproducible, but jobs, history, and (once persisted)
accumulated egress reputation are not. Back up Postgres:

```bash
# Docker Compose deployment
docker compose -f deploy/compose/docker-compose.yml exec -T postgres \
  pg_dump -U rcptto rcptto | gzip > "rcptto-$(date +%F).sql.gz"
```

A daily cron job writing to off-server storage is sufficient. Test a restore
at least once — an untested backup isn't a backup.

---

## 7. First run

Start conservatively. A brand-new IP has no sending reputation, and rcpttō
deliberately ramps new egress identities over several days (50 → 200 → 1,000 →
5,000 probes/day) rather than letting you fire a full list on day one.

1. Verify a handful of addresses on domains you control.
2. Watch the **Egress** page in the dashboard: health, state, quarantine reason.
3. Run a few hundred real addresses; check for elevated `blocked` or
   `greylisted` outcomes.
4. Scale up over days, not hours.

Expect **1,500–2,000 verifications/day** to be comfortable on a single warmed
IP, rising to roughly double that after a couple of months of clean operation.
The provider-policy engine skips Gmail/Yahoo/Microsoft entirely (probing them
is unreliable and costs reputation for no signal), so total addresses processed
per day is typically well above the raw probe count.

---

## 8. Upgrading

```bash
git pull
docker compose -f deploy/compose/docker-compose.yml \
               --env-file deploy/compose/.env up -d --build
```

Schema migrations are embedded in the binary and applied automatically at
startup, inside a transaction. Take a database backup before upgrading.
