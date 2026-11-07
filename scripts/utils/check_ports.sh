#!/usr/bin/env bash
# ==============================================================================
# Endpoint Audit & Handshake Reachability Verifier
# ==============================================================================

set -euo pipefail

HOST="${1:-127.0.0.1}"
PORTS="${2:-443,8443}"

echo ">>> Inspecting listening ports and TLS probes on ${HOST} (${PORTS})..."

IFS=',' read -ra PORT_ARR <<< "$PORTS"
for port in "${PORT_ARR[@]}"; do
  echo -n "Checking port ${port}... "
  if nc -z -w 3 "$HOST" "$port" 2>/dev/null; then
    echo "[OPEN]"
    echo "  Testing TLS SNI handshake probe..."
    if echo | openssl s_client -connect "${HOST}:${port}" -servername www.apple.com -brief 2>&1 | grep -q "CONNECTION ESTABLISHED"; then
      echo "  ✓ TLS Handshake Succeeded"
    else
      echo "  ⚠ TLS Handshake Failed or Masqueraded"
    fi
  else
    echo "[CLOSED / FILTERED]"
  fi
done
