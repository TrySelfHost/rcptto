#!/usr/bin/env bash
#
# preflight.sh — verify an egress IP is usable before building on it.
#
# Run on each agent host, once per egress IP. The checks are ordered by how
# expensive the mistake is to discover later: a blocked port 25 or a mismatched
# PTR makes an IP useless for verification, and a blocklisted IP poisons results
# from day one.
#
#   ./preflight.sh 203.0.113.10 mx1.example.com
#
# Exits non-zero if any check fails.

set -uo pipefail

IP="${1:-}"
HELO="${2:-}"

if [[ -z "$IP" || -z "$HELO" ]]; then
    echo "usage: $0 <egress-ip> <helo-hostname>" >&2
    exit 2
fi

# Missing tools would otherwise surface as false failures — a fresh VPS often
# has neither dnsutils nor iproute2 — so check for them up front and say so.
missing=()
for tool in dig ip timeout; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
done
if (( ${#missing[@]} )); then
    echo "Missing required tools: ${missing[*]}" >&2
    echo >&2
    echo "Install them first, e.g.:" >&2
    echo "  Debian/Ubuntu:  sudo apt-get install -y dnsutils iproute2 coreutils" >&2
    echo "  RHEL/Alma:      sudo dnf install -y bind-utils iproute coreutils" >&2
    exit 2
fi

failures=0
pass() { printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; failures=$((failures + 1)); }
warn() { printf '  \033[33mWARN\033[0m  %s\n' "$1"; }

echo "Preflight for $IP presenting as $HELO"
echo

# --- 1. the IP is actually on this host -------------------------------------
echo "Local address"
if ip -4 addr show 2>/dev/null | grep -qw "$IP"; then
    pass "$IP is configured on this host"
else
    fail "$IP is not configured on any interface — an agent cannot bind it"
fi

# --- 2. forward DNS ----------------------------------------------------------
echo "Forward DNS"
fwd=$(dig +short A "$HELO" 2>/dev/null | tail -1)
if [[ "$fwd" == "$IP" ]]; then
    pass "$HELO resolves to $IP"
elif [[ -z "$fwd" ]]; then
    fail "$HELO does not resolve — create an A record pointing at $IP"
else
    fail "$HELO resolves to $fwd, not $IP"
fi

# --- 3. reverse DNS ----------------------------------------------------------
# Mismatched or missing PTR is the fastest route to being blocked, independent
# of volume. It is set in the VPS provider's control panel, not your DNS host.
echo "Reverse DNS (PTR)"
ptr=$(dig +short -x "$IP" 2>/dev/null | sed 's/\.$//' | tail -1)
if [[ "$ptr" == "$HELO" ]]; then
    pass "$IP resolves back to $HELO (forward-confirmed)"
elif [[ -z "$ptr" ]]; then
    fail "$IP has no PTR record — set it in your provider's panel to $HELO"
else
    fail "$IP has PTR $ptr, which does not match $HELO"
fi

# --- 4. outbound port 25 -----------------------------------------------------
# Many providers block this by default, sometimes silently.
echo "Outbound port 25"
if timeout 10 bash -c "cat < /dev/null > /dev/tcp/gmail-smtp-in.l.google.com/25" 2>/dev/null; then
    pass "outbound port 25 is open"
else
    fail "outbound port 25 is blocked — ask your provider to unblock it"
fi

# --- 5. blocklists -----------------------------------------------------------
# A recycled IP can arrive already listed. Check before building on it.
echo "Blocklists"
rev=$(echo "$IP" | awk -F. '{print $4"."$3"."$2"."$1}')
listed=0
for zone in zen.spamhaus.org bl.spamcop.net b.barracudacentral.org; do
    result=$(dig +short "$rev.$zone" 2>/dev/null | head -1)
    case "$result" in
        127.255.*) warn "$zone: query refused (use your own resolver, not a public one)" ;;
        127.*)     fail "$IP is listed on $zone"; listed=1 ;;
        "")        pass "$zone: not listed" ;;
        *)         warn "$zone: unexpected response $result" ;;
    esac
done
[[ $listed -eq 1 ]] && warn "ask your provider to swap a pre-listed IP rather than warming it"

echo
if [[ $failures -eq 0 ]]; then
    echo "All checks passed. This IP is ready to warm up."
else
    echo "$failures check(s) failed. Fix these before sending probes from $IP."
fi
exit $((failures > 0))
