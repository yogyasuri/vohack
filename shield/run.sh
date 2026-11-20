#!/usr/bin/env bash
# Start the Voyege Security & Fraud Shield dashboard on http://127.0.0.1:8800
set -euo pipefail
cd "$(dirname "$0")"
python3 -c "import fastapi, uvicorn, httpx, yaml" 2>/dev/null || pip install -r requirements.txt
exec python3 -m voyege_shield.server "$@"
