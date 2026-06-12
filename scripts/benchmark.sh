#!/usr/bin/env bash
# benchmark.sh — Run the full D-HotStuff benchmark suite from paper §6.2.
#
# Expected TPS ranges per paper Fig. 4 (1MB payload, 250-byte txs):
#   n=4:  ~133,940 TPS
#   n=10: ~89,123 TPS
#   n=16: ~70,445 TPS
#   n=31: ~53,867 TPS
#
# Usage: ./scripts/benchmark.sh
#
# Results are written to ./results/<timestamp>/

set -euo pipefail

# -------------------------------------------------------------------
# Configuration
# -------------------------------------------------------------------

SIZES=(4 10 16 31)
PAYLOADS=(1 2 3 4 5)  # MB
DURATION="30s"
TX_SIZE=250            # bytes, matching Bitcoin/Ethereum typical tx size
RESULTS_DIR="./results/$(date +%Y%m%d_%H%M%S)"

CLIENT="./bin/client"
KEYGEN_SCRIPT="./scripts/gen_keys.sh"
DEPLOY_SCRIPT="./scripts/deploy_local.sh"

# -------------------------------------------------------------------
# Pre-flight checks
# -------------------------------------------------------------------

echo "==> D-HotStuff Benchmark Suite (paper §6.2 reproduction)"
echo ""

if [[ ! -x "$KEYGEN_SCRIPT" ]]; then
    echo "ERROR: $KEYGEN_SCRIPT not found. Run from project root." >&2
    exit 1
fi

if [[ ! -x "$DEPLOY_SCRIPT" ]]; then
    echo "ERROR: $DEPLOY_SCRIPT not found. Run from project root." >&2
    exit 1
fi

mkdir -p "$RESULTS_DIR"
echo "==> Results will be written to: $RESULTS_DIR"
echo ""

# -------------------------------------------------------------------
# Summary of planned runs
# -------------------------------------------------------------------

TOTAL_RUNS=$(( ${#SIZES[@]} * ${#PAYLOADS[@]} ))
echo "==> Planned: $TOTAL_RUNS benchmark runs"
echo "    Committee sizes: ${SIZES[*]}"
echo "    Payload sizes:   ${PAYLOADS[*]} MB"
echo "    Duration per run: $DURATION"
echo "    Transaction size: $TX_SIZE bytes"
echo ""

# -------------------------------------------------------------------
# Run benchmarks
# -------------------------------------------------------------------

RUN=0
for N in "${SIZES[@]}"; do
    echo "================================================================"
    echo "==> Committee size: n=$N"
    echo "================================================================"
    echo ""

    # Step 1: Generate keys for this committee size.
    KEY_DIR="./keys/bench-$N"
    echo "--- Generating $N key pairs in $KEY_DIR ..."
    "$KEYGEN_SCRIPT" "$N" "$KEY_DIR" > "$RESULTS_DIR/keygen_n${N}.log" 2>&1 || {
        echo "WARNING: keygen failed for n=$N, skipping. See $RESULTS_DIR/keygen_n${N}.log" >&2
        continue
    }

    # Step 2: Start the cluster.
    echo "--- Starting cluster with $N replicas ..."
    "$DEPLOY_SCRIPT" "$N" &
    CLUSTER_PID=$!

    # Give replicas time to start and connect.
    sleep 2

    # Step 3: Run benchmarks for each payload size.
    for PAYLOAD in "${PAYLOADS[@]}"; do
        RUN=$((RUN + 1))
        OUTPUT_FILE="$RESULTS_DIR/n${N}_p${PAYLOAD}MB.json"

        echo "--- [$RUN/$TOTAL_RUNS] n=$N, payload=${PAYLOAD}MB → $OUTPUT_FILE"

        if [[ -x "$CLIENT" ]]; then
            "$CLIENT" \
                --n="$N" \
                --payload="${PAYLOAD}MB" \
                --txsize="$TX_SIZE" \
                --duration="$DURATION" \
                --out="$OUTPUT_FILE" \
                2>&1 | tee "$RESULTS_DIR/run_n${N}_p${PAYLOAD}MB.log" || {
                    echo "WARNING: client run failed for n=$N p=${PAYLOAD}MB" >&2
                }
        else
            echo "    SKIP: $CLIENT not found (build with: make build)" >&2
            # Write a placeholder result.
            cat > "$OUTPUT_FILE" <<EOF
{
  "committee_size": $N,
  "payload_mb": $PAYLOAD,
  "tx_size_bytes": $TX_SIZE,
  "duration": "$DURATION",
  "status": "skipped",
  "reason": "client binary not built"
}
EOF
        fi

        echo ""
    done

    # Step 4: Kill the cluster.
    echo "--- Stopping cluster (PID: $CLUSTER_PID) ..."
    kill "$CLUSTER_PID" 2>/dev/null || true
    wait "$CLUSTER_PID" 2>/dev/null || true

    echo ""
done

# -------------------------------------------------------------------
# Run Go benchmarks
# -------------------------------------------------------------------

echo "================================================================"
echo "==> Running Go benchmarks (internal/metrics) ..."
echo "================================================================"
echo ""

GO_BENCH_OUTPUT="$RESULTS_DIR/go_bench.txt"
go test -bench=. -benchmem -count=3 ./internal/metrics/ 2>&1 | tee "$GO_BENCH_OUTPUT" || {
    echo "WARNING: Go benchmarks failed. See $GO_BENCH_OUTPUT" >&2
}

echo ""

# -------------------------------------------------------------------
# Summary
# -------------------------------------------------------------------

echo "================================================================"
echo "==> Benchmark suite complete!"
echo "================================================================"
echo ""
echo "Results written to: $RESULTS_DIR"
echo ""
echo "Files:"
ls -la "$RESULTS_DIR/" 2>/dev/null || dir "$RESULTS_DIR/" 2>/dev/null
echo ""
echo "To analyze results:"
echo "  cat $GO_BENCH_OUTPUT"
echo "  jq '.' $RESULTS_DIR/n4_p1MB.json"
