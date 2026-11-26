#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e .[dev]

echo "Checking optional binaries..."
for bin in nmap tshark nuclei naabu amass subfinder dnsx httpx; do
  if command -v "$bin" >/dev/null 2>&1; then
    echo "  [ok] $bin"
  else
    echo "  [missing] $bin"
  fi
done

python -m backend.cli init-db
echo "Setup complete. Activate with: source .venv/bin/activate"
