#!/usr/bin/env bash
# run-audit-local.sh
# Runs all 4 audit scripts against a local moto server.
# Expects moto_server to already be running on port 5000.
#
# Usage:
#   bash tests/run-audit-local.sh
#   bash tests/run-audit-local.sh --port 5000

set -euo pipefail

PORT="${1:-5000}"
ENDPOINT="http://localhost:$PORT"

# ── Colors ────────────────────────────────────────────────────────
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

SCRIPTS_DIR="$(cd "$(dirname "$0")/../scripts" && pwd)"

header() {
  echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════${RESET}"
  echo -e "${BOLD}${CYAN}  $1${RESET}"
  echo -e "${BOLD}${CYAN}══════════════════════════════════════════${RESET}"
}

# ── Check moto is running ─────────────────────────────────────────
echo -e "\n${BOLD}Checking moto server at $ENDPOINT...${RESET}"
if ! curl -s "$ENDPOINT" > /dev/null 2>&1; then
  echo -e "${RED}ERROR: moto server not running at $ENDPOINT${RESET}"
  echo ""
  echo "Start it first:"
  echo -e "  ${CYAN}moto_server -p $PORT${RESET}"
  exit 1
fi
echo -e "${GREEN}moto server is up${RESET}"

# ── Point AWS CLI at moto ─────────────────────────────────────────
export AWS_DEFAULT_REGION="ap-south-1"
export AWS_ACCESS_KEY_ID="test"
export AWS_SECRET_ACCESS_KEY="test"
export AWS_ENDPOINT_URL="$ENDPOINT"

# Disable pagination prompts
export AWS_PAGER=""

# ── Track results ─────────────────────────────────────────────────
TOTAL_CRITICAL=0
TOTAL_WARNING=0
RESULTS=()

run_audit() {
  local script="$1"
  local name="$2"

  header "$name"

  local output
  local exit_code=0

  output=$(bash "$SCRIPTS_DIR/$script" --region ap-south-1 2>&1) || exit_code=$?

  echo "$output"

  local crits warnings
  crits=$(echo "$output" | grep -c '\[CRITICAL\]' 2>/dev/null || true)
  warnings=$(echo "$output" | grep -c '\[WARNING\]' 2>/dev/null || true)
  # grep -c returns empty string if no match on some systems — default to 0
  crits="${crits:-0}"
  warnings="${warnings:-0}"
  # strip any whitespace/newlines
  crits=$(echo "$crits" | tr -d '[:space:]')
  warnings=$(echo "$warnings" | tr -d '[:space:]')

  TOTAL_CRITICAL=$((TOTAL_CRITICAL + crits))
  TOTAL_WARNING=$((TOTAL_WARNING + warnings))

  if [ "$exit_code" -ne 0 ]; then
    RESULTS+=("${RED}FAILED${RESET}  $name — $crits critical, $warnings warnings")
  else
    RESULTS+=("${GREEN}PASSED${RESET}  $name — $crits critical, $warnings warnings")
  fi
}

# ── Run all 4 scripts ─────────────────────────────────────────────
echo -e "\n${BOLD}Running all audit scripts against moto...${RESET}"

run_audit "audit-iam.sh"     "IAM Security Audit"
run_audit "audit-ec2.sh"     "EC2 Security Audit"
run_audit "audit-network.sh" "Network Security Audit"
run_audit "audit-s3-rds.sh"  "S3 + RDS + Lambda Audit"

# ── Summary ───────────────────────────────────────────────────────
echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════${RESET}"
echo -e "${BOLD}  OVERALL RESULTS${RESET}"
echo -e "${BOLD}${CYAN}══════════════════════════════════════════${RESET}"

for result in "${RESULTS[@]}"; do
  echo -e "  $result"
done

echo ""
echo -e "  ${RED}Total critical: $TOTAL_CRITICAL${RESET}"
echo -e "  ${YELLOW}Total warnings: $TOTAL_WARNING${RESET}"

if [ "$TOTAL_CRITICAL" -gt 0 ]; then
  echo -e "\n${RED}${BOLD}Vulnerable environment confirmed — $TOTAL_CRITICAL critical findings detected.${RESET}"
  echo -e "${CYAN}These are expected — this is a deliberately misconfigured test environment.${RESET}"
else
  echo -e "\n${YELLOW}${BOLD}No critical findings — check that setup_vulnerable_env.py ran successfully.${RESET}"
fi

echo ""