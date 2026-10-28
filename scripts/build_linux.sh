#!/usr/bin/env bash
# Buduje pakiety Linux (CLI + GUI). Wymaga Pythona 3.11+ i zależności: pip install -e ".[dev]"
set -euo pipefail
cd "$(dirname "$0")/.."
python scripts/build.py "$@"
