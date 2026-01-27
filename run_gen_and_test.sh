#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GEN_DIR="${ROOT_DIR}/test/testchain-generator"
BLOCKSCIPY_DIR="${ROOT_DIR}/blockscipy"
PARSER_BIN_DIR="${ROOT_DIR}/build-dbg/tools/parser"
LIB_DIR="${ROOT_DIR}/build-dbg/src"
VENV_PY="${ROOT_DIR}/.venv/bin/python"

BITCOIND_BIN="${BITCOIND_BIN:-/home/user/Documents/DEV/blocksci-docker/bitcoin/build/bin/bitcoind}"

echo "Using bitcoind: ${BITCOIND_BIN}"

"${VENV_PY}" "${GEN_DIR}/generate_chain.py" --exec="${BITCOIND_BIN}"

PATH="${PARSER_BIN_DIR}:${PATH}" \
PYTHONPATH="${BLOCKSCIPY_DIR}" \
LD_LIBRARY_PATH="${LIB_DIR}" \
pytest "${ROOT_DIR}/test/blockscipy" -q -k test_clustering_default_heuristic
