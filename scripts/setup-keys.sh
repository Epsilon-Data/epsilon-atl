#!/bin/bash
# Generate operator keypair + coordinator-bench keypair for benchmarks.
# Run from the epsilon-atl repo root.
set -euo pipefail

KEYS_DIR="$(dirname "$0")/../keys"
COORD_DIR="${KEYS_DIR}/coordinators"

mkdir -p "$KEYS_DIR" "$COORD_DIR"

# 1. Operator keypair (signs STHs)
if [ ! -f "$KEYS_DIR/operator.key" ]; then
    echo "Generating operator keypair..."
    go run ./cmd/atl keygen -o "$KEYS_DIR"
else
    echo "Operator keypair already exists."
fi

# 2. Coordinator-bench keypair (signs entry submissions from benchmarks)
if [ ! -f "$COORD_DIR/coordinator-bench.pub" ]; then
    echo "Generating coordinator-bench keypair..."
    openssl genpkey -algorithm ed25519 -out "$KEYS_DIR/coordinator-bench.key" 2>/dev/null
    openssl pkey -in "$KEYS_DIR/coordinator-bench.key" -pubout -out "$COORD_DIR/coordinator-bench.pub"
    echo "  Private: $KEYS_DIR/coordinator-bench.key  (copy to evaluation/keys/)"
    echo "  Public:  $COORD_DIR/coordinator-bench.pub  (loaded by ATL server)"
else
    echo "Coordinator-bench keypair already exists."
fi

echo ""
echo "Keys directory:"
find "$KEYS_DIR" -type f | sort
echo ""
echo "Next steps:"
echo "  1. docker compose up -d"
echo "  2. Copy $KEYS_DIR/coordinator-bench.key to evaluation/keys/submitter_ed25519.pem"
echo "  3. go run ./cmd/seed           # seed sample data"
echo "  4. go run ./cmd/seed --count N # bulk seed for benchmarks"
