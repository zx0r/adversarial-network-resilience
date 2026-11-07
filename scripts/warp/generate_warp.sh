#!/usr/bin/env bash
# ==============================================================================
# Cloudflare WARP WireGuard Profile Generator
# Registers a client keypair with Cloudflare API and formats wg0.conf
# ==============================================================================

set -euo pipefail

OUTPUT_CONF="${1:-warp.conf}"

echo ">>> Generating WireGuard private/public keypair..."
if ! command -v wg &>/dev/null; then
  echo "Error: wireguard-tools ('wg') is required." >&2
  exit 1
fi

PRIVATE_KEY=$(wg genkey)
PUBLIC_KEY=$(echo "$PRIVATE_KEY" | wg pubkey)

echo ">>> Registering client with Cloudflare WARP API..."
RESPONSE=$(curl -s -X POST "https://api.cloudflareclient.com/v0a2158/reg" \
  -H "User-Agent: okhttp/3.12.1" \
  -H "Content-Type: application/json; charset=UTF-8" \
  -d "{
    \"key\": \"${PUBLIC_KEY}\",
    \"install_id\": \"\",
    \"fcm_token\": \"\",
    \"tos\": \"$(date -u +'%Y-%m-%dT%H:%M:%SZ')\",
    \"model\": \"PC\",
    \"type\": \"Android\",
    \"locale\": \"en_US\"
  }")

ID=$(echo "$RESPONSE" | jq -r '.result.id')
TOKEN=$(echo "$RESPONSE" | jq -r '.result.token')
IPV4=$(echo "$RESPONSE" | jq -r '.result.config.interface.addresses.v4')
IPV6=$(echo "$RESPONSE" | jq -r '.result.config.interface.addresses.v6')
PEER_PUB=$(echo "$RESPONSE" | jq -r '.result.config.peers[0].public_key')
ENDPOINT=$(echo "$RESPONSE" | jq -r '.result.config.peers[0].endpoint.host')

if [ -z "$IPV4" ] || [ "$IPV4" = "null" ]; then
  echo "Error: Failed to register with WARP API. Response: $RESPONSE" >&2
  exit 1
fi

echo ">>> Writing WireGuard profile to ${OUTPUT_CONF}..."
cat << EOF > "${OUTPUT_CONF}"
# Cloudflare WARP Registration
# Account ID: ${ID}
# Account Token: ${TOKEN}

[Interface]
PrivateKey = ${PRIVATE_KEY}
Address = ${IPV4}/32, ${IPV6}/128
DNS = 1.1.1.1, 2606:4700:4700::1111

[Peer]
PublicKey = ${PEER_PUB}
Endpoint = ${ENDPOINT}
AllowedIPs = 0.0.0.0/0, ::/0
EOF

echo "✓ Successfully generated ${OUTPUT_CONF} for client ${ID}."
