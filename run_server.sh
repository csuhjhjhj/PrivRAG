#!/usr/bin/env bash
set -euo pipefail

export PRIVRAG_HOST="${PRIVRAG_HOST:-0.0.0.0}"
export PRIVRAG_PORT="${PRIVRAG_PORT:-5000}"
export PRIVRAG_DEBUG="${PRIVRAG_DEBUG:-0}"

python3 backend/app.py
