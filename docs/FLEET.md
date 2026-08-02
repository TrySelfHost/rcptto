# Deploying a probe-agent fleet

An egress IP can only be dialled from the machine that owns it. To pool IPs
across several servers, the control plane keeps all the intelligence — funnel,
provider policy, reputation, scheduling, dashboard — and delegates only the SMTP
probe to a small agent on each box.

This guide covers a fleet. For the control plane itself see
[`DEPLOYMENT.md`](DEPLOYMENT.md).

---

## Before you buy anything

**Confirm outbound port 25 with your provider, in writing.** Policies differ
sharply and are the single thing most likely to invalidate a plan after you have
paid. Some providers leave it open; others block it by default and unblock only
on request; others never allow it. Ask two questions:

1. Is outbound port 25 open, and if not, what is the unblock process?
2. Does an unblock apply to the whole server or per-IP?

The second matters: if it is per-IP, provisioning ten IPs means ten requests,
and your rollout is measured in days.

**Do not put the whole fleet on one provider.** Blocklists and mailbox providers
assess reputation at the `/24` and ASN level, not per IP. Ten IPs in adjacent
ranges on one account can be flagged together — and that is precisely the case
the reputation manager cannot route around, because there is nowhere clean left
to route to. Splitting even two of five servers to a second provider removes
that single point of failure.

---

## 1. Plan the identities

One agent serves one IP. Give every identity a stable id used consistently in
three places: the agent's `RCPTTO_WORKER_ID`, its env filename, and the control
plane's `RCPTTO_WORKERS` list. A mismatch is caught rather than guessed — the
control plane refuses an agent whose reported id disagrees with its
configuration, because routing to it would credit reputation to the wrong IP.

| Identity | Host | IP | HELO | Agent port |
|---|---|---|---|---|
| `eg_vps1a` | vps1 | 203.0.113.10 | mx1.example.com | 9090 |
| `eg_vps1b` | vps1 | 203.0.113.11 | mx2.example.com | 9091 |
| `eg_vps2a` | vps2 | 203.0.113.20 | mx3.example.com | 9090 |
| … | | | | |

Generate one shared token for the whole fleet:

```bash
openssl rand -base64 32
```

---

## 2. Configure each additional IP on its host

Additional IPs are usually not configured automatically. On a Debian/Ubuntu host
using netplan, add the second address to the existing interface:

```yaml
# /etc/netplan/01-netcfg.yaml
network:
  version: 2
  ethernets:
    eth0:
      addresses:
        - 203.0.113.10/24     # primary
        - 203.0.113.11/32     # additional
      # gateway and nameservers unchanged
```

```bash
sudo netplan apply
ip -4 addr show eth0     # both addresses should be listed
```

Then set the **PTR record for each IP** in your provider's control panel — not
your DNS host — pointing at that IP's HELO hostname, and create the matching
forward `A` record at your DNS host.

---

## 3. Preflight every IP

Do this before warming anything. A blocked port 25 or a mismatched PTR makes an
IP useless for verification, and a pre-listed IP poisons results from day one —
all far cheaper to find now than after a week of warm-up.

```bash
./deploy/scripts/preflight.sh 203.0.113.10 mx1.example.com
./deploy/scripts/preflight.sh 203.0.113.11 mx2.example.com
```

The script checks that the IP is bound locally, that forward and reverse DNS
agree, that outbound port 25 works, and that the IP is not already on Spamhaus,
SpamCop, or Barracuda. **If an IP arrives blocklisted, ask your provider to swap
it rather than trying to warm it.**

---

## 4. Install the agents

### systemd (recommended)

The unit is a template, so one host runs several agents without duplicating it.

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin rcptto
sudo install -m 0755 rcptto-worker /usr/local/bin/rcptto-worker
sudo install -d -o root -g rcptto -m 0750 /etc/rcptto
sudo install -m 0644 deploy/systemd/rcptto-worker@.service /etc/systemd/system/
```

One env file per IP, named after the identity (mode `0640`, `root:rcptto` — it
holds the fleet token):

```bash
sudo cp deploy/systemd/worker.env.example /etc/rcptto/worker-eg_vps1a.env
sudo chmod 0640 /etc/rcptto/worker-eg_vps1a.env
sudo chown root:rcptto /etc/rcptto/worker-eg_vps1a.env
sudoedit /etc/rcptto/worker-eg_vps1a.env
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now rcptto-worker@eg_vps1a
sudo systemctl enable --now rcptto-worker@eg_vps1b     # second IP, same host

journalctl -u 'rcptto-worker@*' -f
```

### Docker Compose

```bash
cp deploy/compose/worker.env.example deploy/compose/worker.env
$EDITOR deploy/compose/worker.env
docker compose -f deploy/compose/docker-compose.worker.yml \
               --env-file deploy/compose/worker.env up -d --build
```

Agents run with `network_mode: host` deliberately: binding a specific source IP
requires the host's real addresses, which a bridge network hides.

---

## 5. Firewall

Agents accept probe requests over the network, so the port must be reachable by
the control plane — and by nothing else. An unauthenticated or exposed agent
lets a stranger probe mail servers from your IP.

```bash
sudo ufw allow from <control-plane-ip> to any port 9090 proto tcp
sudo ufw allow from <control-plane-ip> to any port 9091 proto tcp
sudo ufw deny 9090
sudo ufw deny 9091
```

The token is required regardless, but restricting by source IP means an
unauthenticated request never reaches the process.

---

## 6. Register the fleet with the control plane

```bash
RCPTTO_WORKERS="eg_vps1a=http://203.0.113.10:9090,eg_vps1b=http://203.0.113.11:9091,eg_vps2a=http://203.0.113.20:9090"
RCPTTO_WORKER_TOKEN="<the shared token>"
```

Restart the control plane and open **Servers** in the dashboard. Every agent
should appear `online` within 30 seconds, with its discovered IP and HELO. An
agent that cannot be reached shows the exact dial error, and its identity is
skipped during routing until it returns — without disturbing whatever warm-up
progress or quarantine it had earned.

Prefer HTTPS between control plane and agents if they cross the public internet.
The token is sent as a bearer header; over plain HTTP it is exposed in transit.

---

## 7. Warm up, slowly

Every new identity starts in `warming` and ramps its daily cap over several days
(50 → 200 → 1,000 → 5,000). This is calendar time, not a setting: ten fresh IPs
do not give you ten IPs' throughput on day one.

**Stagger the fleet.** Bringing all ten online together means all ten are at
their lowest cap simultaneously, and any systemic mistake — a wrong HELO, a bad
subnet — is repeated ten times before you notice. Add two, watch the Egress page
for a few days, then add the rest.

Expect roughly 1,500–2,000 verifications/day per warmed IP as a comfortable
sustained figure, rising to perhaps double that after a couple of months of
clean operation. Because provider policy skips Gmail, Yahoo, and Microsoft
entirely, the number of *addresses processed* is typically far higher than the
number of probes sent — the per-list report shows that split.

---

## 8. Watch for

- **Servers page** — an agent offline for more than a few minutes.
- **Egress page** — an identity moving to `quarantined`, with the reason.
- **Correlated failures.** Several identities degrading together points at
  something shared: a subnet-level listing, a provider-wide block, or a
  configuration mistake repeated across hosts. That is the failure mode
  single-provider fleets are prone to, and no amount of per-IP routing fixes it.
