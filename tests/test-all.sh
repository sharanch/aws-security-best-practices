#!/usr/bin/env bash
# test-all.sh
# One command to run the full test cycle:
#   1. Create / activate a Python venv
#   2. Install moto + boto3 into the venv
#   3. Start moto server
#   4. Create vulnerable resources
#   5. Run all 4 audit scripts
#   6. Print findings summary
#   7. Stop moto server
#
# Usage:
#   bash tests/test-all.sh

set -euo pipefail

TESTS_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$TESTS_DIR/.." && pwd)"
VENV_DIR="$TESTS_DIR/.venv"
PORT=5000
ENDPOINT="http://localhost:$PORT"
MOTO_PID=""

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ── Cleanup on exit ───────────────────────────────────────────────
cleanup() {
  if [ -n "$MOTO_PID" ] && kill -0 "$MOTO_PID" 2>/dev/null; then
    echo -e "\n${CYAN}Stopping moto server (PID $MOTO_PID)...${RESET}"
    kill "$MOTO_PID" 2>/dev/null || true
    wait "$MOTO_PID" 2>/dev/null || true
    echo -e "${GREEN}moto server stopped.${RESET}"
  fi
}
trap cleanup EXIT INT TERM

# ── Banner ────────────────────────────────────────────────────────
echo -e "\n${BOLD}${CYAN}"
echo "  ┌─────────────────────────────────────────────────────┐"
echo "  │   aws-security-best-practices                       │"
echo "  │   Local Audit Test Runner                           │"
echo "  │   Uses moto to simulate AWS — no real account needed│"
echo "  └─────────────────────────────────────────────────────┘"
echo -e "${RESET}"

# ── Check system dependencies ─────────────────────────────────────
echo -e "${BOLD}Checking system dependencies...${RESET}"

check_dep() {
  if command -v "$1" &>/dev/null; then
    echo -e "  ${GREEN}[found]${RESET}   $1"
  else
    echo -e "  ${RED}[missing]${RESET} $1 — install with: $2"
    exit 1
  fi
}

check_dep "python3" "sudo apt install python3 python3-venv"
check_dep "aws"     "https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html"
check_dep "curl"    "sudo apt install curl"

# ── Set up venv ───────────────────────────────────────────────────
echo -e "\n${BOLD}Setting up Python virtual environment...${RESET}"

if [ ! -d "$VENV_DIR" ]; then
  echo -e "  Creating venv at tests/.venv"
  python3 -m venv "$VENV_DIR"
  echo -e "  ${GREEN}[created]${RESET} $VENV_DIR"
else
  echo -e "  ${GREEN}[exists]${RESET}  $VENV_DIR"
fi

# Activate venv
# shellcheck source=/dev/null
source "$VENV_DIR/bin/activate"
echo -e "  ${GREEN}[active]${RESET}  venv activated"

# Install / upgrade deps quietly
echo -e "  Installing dependencies from requirements.txt..."
pip install --quiet --upgrade pip
pip install --quiet -r "$TESTS_DIR/requirements.txt"
echo -e "  ${GREEN}[ready]${RESET}   moto + boto3 installed in venv"

# ── Start moto server ─────────────────────────────────────────────
echo -e "\n${BOLD}Starting moto server on port $PORT...${RESET}"

# Kill any existing process on that port
lsof -ti ":$PORT" | xargs kill -9 2>/dev/null || true

moto_server -p "$PORT" > /tmp/moto.log 2>&1 &
MOTO_PID=$!

# Wait for moto to be ready
echo -n "  Waiting for moto to be ready"
for i in $(seq 1 20); do
  if curl -s "$ENDPOINT" > /dev/null 2>&1; then
    echo -e " ${GREEN}ready${RESET}"
    break
  fi
  echo -n "."
  sleep 0.5
  if [ $i -eq 20 ]; then
    echo -e "\n${RED}moto failed to start. Check /tmp/moto.log${RESET}"
    exit 1
  fi
done

echo -e "  ${GREEN}moto server running (PID $MOTO_PID)${RESET}"

# ── Create vulnerable resources ───────────────────────────────────
echo -e "\n${BOLD}Creating deliberately misconfigured resources...${RESET}"
python3 "$TESTS_DIR/setup_vulnerable_env.py" --endpoint "$ENDPOINT"

# ── Run audit scripts ─────────────────────────────────────────────
bash "$TESTS_DIR/run-audit-local.sh"

echo -e "\n${BOLD}${GREEN}Test run complete.${RESET}"
echo -e "moto server will stop automatically on exit.\n"