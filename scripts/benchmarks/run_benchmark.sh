#!/usr/bin/env bash
# ==============================================================================
# Modern Network Protocols - Automated WAN Impairment Benchmark Runner
# Standardized sweep across loss (0%, 2%, 5%) and latency (20ms, 100ms, 200ms)
# ==============================================================================

set -euo pipefail

TARGET_HOST="${1:-172.28.0.10}"
TEST_DURATION="${TEST_DURATION:-10}"
STREAMS="${STREAMS:-4}"
OUTPUT_FILE="${OUTPUT_FILE:-benchmark_results.json}"

echo "=========================================================="
echo " Starting Network Protocol Performance Benchmark"
echo " Target Endpoint : ${TARGET_HOST}"
echo " Stream Duration : ${TEST_DURATION}s (Parallel Streams: ${STREAMS})"
echo " Output File     : ${OUTPUT_FILE}"
echo "=========================================================="

# Profile Matrix: [Loss %, Delay ms (one-way)]
declare -a PROFILES=(
  "0 10"    # Baseline: 0% loss, ~20ms RTT
  "2 50"    # Moderate impairment: 2% loss, ~100ms RTT
  "5 100"   # Severe impairment: 5% loss, ~200ms RTT
)

results="[]"

for profile in "${PROFILES[@]}"; do
  read -r loss delay <<< "$profile"
  rtt=$((delay * 2))
  echo ""
  echo ">>> Applying Network Impairment Profile: ${loss}% loss, ${rtt}ms RTT..."

  # Configure Linux tc netem on wan-emulator container if accessible locally
  if command -v docker &>/dev/null && docker ps --format '{{.Names}}' | grep -q "mnp-wan-emulator"; then
    docker exec mnp-wan-emulator tc qdisc change dev eth0 root netem delay "${delay}ms" loss "${loss}%" 2>/dev/null || \
    docker exec mnp-wan-emulator tc qdisc add dev eth0 root netem delay "${delay}ms" loss "${loss}%"
  fi

  # Allow network queue to stabilize
  sleep 2

  echo ">>> Measuring TCP Throughput (iperf3)..."
  if command -v iperf3 &>/dev/null; then
    iperf_out=$(iperf3 -c "${TARGET_HOST}" -t "${TEST_DURATION}" -P "${STREAMS}" -J 2>/dev/null || echo '{"error": "iperf3 connection failed"}')
    throughput_mbps=$(echo "$iperf_out" | jq -r '.end.sum_received.bits_per_second // 0' | awk '{printf "%.2f", $1 / 1000000}')
  else
    throughput_mbps="N/A (iperf3 not installed locally)"
  fi

  echo ">>> Measured Throughput: ${throughput_mbps} Mbps"

  record=$(jq -n \
    --arg loss "$loss" \
    --arg rtt "$rtt" \
    --arg throughput "$throughput_mbps" \
    '{loss_percent: ($loss | tonumber), rtt_ms: ($rtt | tonumber), throughput_mbps: ($throughput | tonumber)}')

  results=$(echo "$results" | jq --argjson entry "$record" '. += [$entry]')
done

echo "$results" > "$OUTPUT_FILE"
echo ""
echo "=========================================================="
echo " Benchmark suite completed successfully."
echo " Results persisted to ${OUTPUT_FILE}."
echo "=========================================================="
