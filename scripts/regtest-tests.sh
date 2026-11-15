#!/usr/bin/env bash
# Run the #[ignore]d regtest end-to-end tests, and the scripted demo binaries,
# against a throwaway node.
#
# Starts a MATT-enabled `bitcoind` (CCV + CTV, e.g. Bitcoin Inquisition) on a
# temporary datadir, creates and funds `testwallet`, runs the ignored tests,
# and stops the node again. Nothing outside the temporary directory is touched.
#
#   scripts/regtest-tests.sh                 # every ignored test
#   scripts/regtest-tests.sh test_vault      # extra arguments go to the test binary
#
# Environment:
#   BITCOIND          the node binary            (default: bitcoind on PATH)
#   BITCOIN_CLI       its CLI                    (default: next to BITCOIND, else PATH)
#   BITCOIN_RPC_PORT  RPC port for the node      (default: 18443)
set -euo pipefail

BITCOIND=${BITCOIND:-bitcoind}
if [[ -z ${BITCOIN_CLI:-} ]]; then
    sibling="$(dirname "$(command -v "$BITCOIND" || echo "$BITCOIND")")/bitcoin-cli"
    if [[ -x $sibling ]]; then BITCOIN_CLI=$sibling; else BITCOIN_CLI=bitcoin-cli; fi
fi
PORT=${BITCOIN_RPC_PORT:-18443}

command -v "$BITCOIND" >/dev/null || { echo "error: '$BITCOIND' not found; set BITCOIND" >&2; exit 1; }
command -v "$BITCOIN_CLI" >/dev/null || { echo "error: '$BITCOIN_CLI' not found; set BITCOIN_CLI" >&2; exit 1; }

datadir=$(mktemp -d)
cli() { "$BITCOIN_CLI" -regtest -datadir="$datadir" -rpcport="$PORT" "$@"; }
cleanup() {
    status=$?
    # On failure, the node's own log is usually the fastest explanation.
    if [[ $status -ne 0 && -f $datadir/regtest/debug.log ]]; then
        echo "--- last lines of the node's debug.log ---" >&2
        tail -n 40 "$datadir/regtest/debug.log" >&2
    fi
    cli stop >/dev/null 2>&1 || true
    # Give the node a moment to flush before its datadir disappears.
    for _ in $(seq 1 50); do
        [[ -f $datadir/regtest/bitcoind.pid ]] || break
        sleep 0.1
    done
    rm -rf "$datadir"
}
trap cleanup EXIT

# The tests broadcast zero-fee transactions and look up arbitrary funding
# transactions, hence the relay-fee and txindex settings.
"$BITCOIND" -regtest -datadir="$datadir" -daemon -listen=0 -rpcport="$PORT" \
    -txindex=1 -fallbackfee=0.0001 -minrelaytxfee=0 -blockmintxfee=0 >/dev/null

if ! cli -rpcwait -rpcwaittimeout=30 getblockcount >/dev/null; then
    echo "error: the node did not come up on RPC port $PORT (already in use?)" >&2
    exit 1
fi

cli createwallet testwallet >/dev/null
address=$(cli -rpcwallet=testwallet getnewaddress)
cli generatetoaddress 201 "$address" >/dev/null

# Point the tests at this node, and only this node.
unset BITCOIN_RPC_USER BITCOIN_RPC_PASSWORD
export BITCOIN_RPC_URL="http://127.0.0.1:$PORT"
export BITCOIN_RPC_COOKIE="$datadir/regtest/.cookie"

cd "$(dirname "$0")/.."
# One thread: the tests share the node's wallet and its chain tip.
cargo test --all-features --tests -- --ignored --test-threads=1 "$@"

# With no test filter, also run the scripted demo binaries end to end: they are
# otherwise only compiled, never executed.
if [[ $# -eq 0 ]]; then
    cargo run --quiet --all-features --example counter -- --regtest
    cargo run --quiet --all-features --example aggregate_exits
    cargo run --quiet --all-features --example wallet_funding
    for script in examples/vault/scripts/*.txt; do
        cargo run --quiet --all-features --example vault -- --script "$script"
    done
fi
