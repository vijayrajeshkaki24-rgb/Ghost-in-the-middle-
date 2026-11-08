#!/usr/bin/env bash
# Starts the ACASE API (port 5000) and dashboard (port 5173).
# Optional lab services: ./start_acase.sh --lab   (DVWA on :8080, Ollama on :11434 via Docker)
set -euo pipefail
cd "$(dirname "$0")"

[ -f .env ] || { cp .env.example .env; echo "[*] Created .env from .env.example - edit it for SMTP/Ollama."; }

command -v python3 >/dev/null || { echo "python3 missing"; exit 1; }
command -v node    >/dev/null || { echo "node missing"; exit 1; }

if [ "${1:-}" = "--lab" ]; then
  command -v docker >/dev/null || { echo "docker missing"; exit 1; }
  echo "[*] Starting lab services (DVWA, Ollama)..."
  docker compose up -d dvwa ollama
fi

[ -d venv ] || python3 -m venv venv
# shellcheck disable=SC1091
source venv/bin/activate
pip install -q -r requirements.txt

(cd acase-dashboard && [ -d node_modules ] || npm install --silent)

echo "[*] API       -> http://localhost:5000/api/health"
python -m backend.app &
API_PID=$!
trap 'kill $API_PID 2>/dev/null' EXIT

echo "[*] Dashboard -> http://localhost:5173"
cd acase-dashboard && npm run dev
