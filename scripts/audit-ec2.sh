#!/usr/bin/env bash
# audit-ec2.sh — EC2 and compute security audit script
# Usage: ./audit-ec2.sh [--profile <aws-profile>] [--region <region>]

set -euo pipefail

# ─── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ─── Argument Parsing ─────────────────────────────────────────────────────────
PROFILE=""
REGION="ap-south-1"

while [[ $# -gt 0 ]]; do
  case $1 in
    --profile) PROFILE="--profile $2"; shift 2 ;;
    --region)  REGION="$2"; shift 2 ;;
    *) echo "Unknown argument: $1"; exit 1 ;;
  esac
done

AWS="aws $PROFILE --region $REGION"
CRITICAL_COUNT=0
WARNING_COUNT=0

critical() { echo -e "${RED}[CRITICAL]${RESET} $1"; ((CRITICAL_COUNT++)); }
warning()  { echo -e "${YELLOW}[WARNING] ${RESET} $1"; ((WARNING_COUNT++)); }
pass()     { echo -e "${GREEN}[PASS]    ${RESET} $1"; }
info()     { echo -e "${CYAN}[INFO]    ${RESET} $1"; }
header()   { echo -e "\n${BOLD}══════════════════════════════════════════${RESET}"; \
             echo -e "${BOLD}  $1${RESET}"; \
             echo -e "${BOLD}══════════════════════════════════════════${RESET}"; }

# ─── 1. IMDSv2 Enforcement ────────────────────────────────────────────────────
header "1. IMDSv2 Enforcement"

INSTANCES=$($AWS ec2 describe-instances \
  --query 'Reservations[*].Instances[*].[InstanceId,MetadataOptions.HttpTokens,State.Name,Tags[?Key==`Name`].Value|[0]]' \
  --output text 2>/dev/null || echo "")

if [[ -z "$INSTANCES" ]]; then
  info "No EC2 instances found in region $REGION"
else
  IMDSV1_COUNT=0
  while IFS=$'\t' read -r instance_id http_tokens state name; do
    [[ "$state" != "running" ]] && continue
    name="${name:-unnamed}"
    if [[ "$http_tokens" == "optional" ]]; then
      critical "Instance $instance_id ($name) has IMDSv1 enabled — vulnerable to SSRF credential theft"
      ((IMDSV1_COUNT++))
    else
      pass "Instance $instance_id ($name) enforces IMDSv2"
    fi
  done <<< "$INSTANCES"

  [[ $IMDSV1_COUNT -eq 0 ]] && pass "All running instances enforce IMDSv2"
fi

# ─── 2. Public IP Exposure ────────────────────────────────────────────────────
header "2. Public IP Exposure"

$AWS ec2 describe-instances \
  --filters "Name=instance-state-name,Values=running" \
  --query 'Reservations[*].Instances[*].[InstanceId,PublicIpAddress,Tags[?Key==`Name`].Value|[0]]' \
  --output text 2>/dev/null | while IFS=$'\t' read -r instance_id public_ip name; do
  [[ -z "$public_ip" || "$public_ip" == "None" ]] && continue
  name="${name:-unnamed}"
  warning "Instance $instance_id ($name) has public IP: $public_ip — verify this is intentional"
done

# ─── 3. Security Groups — SSH/RDP Open to World ───────────────────────────────
header "3. Security Groups — Dangerous Inbound Rules"

# SSH open to world
SSH_OPEN=$($AWS ec2 describe-security-groups \
  --filters \
    "Name=ip-permission.from-port,Values=22" \
    "Name=ip-permission.to-port,Values=22" \
    "Name=ip-permission.cidr,Values=0.0.0.0/0" \
  --query 'SecurityGroups[*].[GroupId,GroupName]' \
  --output text 2>/dev/null || echo "")

if [[ -n "$SSH_OPEN" ]]; then
  while IFS=$'\t' read -r sg_id sg_name; do
    critical "Security group $sg_id ($sg_name) has SSH (22) open to 0.0.0.0/0"
  done <<< "$SSH_OPEN"
else
  pass "No security groups have SSH open to 0.0.0.0/0"
fi

# RDP open to world
RDP_OPEN=$($AWS ec2 describe-security-groups \
  --filters \
    "Name=ip-permission.from-port,Values=3389" \
    "Name=ip-permission.to-port,Values=3389" \
    "Name=ip-permission.cidr,Values=0.0.0.0/0" \
  --query 'SecurityGroups[*].[GroupId,GroupName]' \
  --output text 2>/dev/null || echo "")

if [[ -n "$RDP_OPEN" ]]; then
  while IFS=$'\t' read -r sg_id sg_name; do
    critical "Security group $sg_id ($sg_name) has RDP (3389) open to 0.0.0.0/0"
  done <<< "$RDP_OPEN"
else
  pass "No security groups have RDP open to 0.0.0.0/0"
fi

# All ports open to world (rule allowing all traffic)
ALL_OPEN=$($AWS ec2 describe-security-groups \
  --filters "Name=ip-permission.cidr,Values=0.0.0.0/0" \
  --query 'SecurityGroups[?IpPermissions[?IpProtocol==`-1`]].[GroupId,GroupName]' \
  --output text 2>/dev/null || echo "")

if [[ -n "$ALL_OPEN" ]]; then
  while IFS=$'\t' read -r sg_id sg_name; do
    critical "Security group $sg_id ($sg_name) allows ALL traffic from 0.0.0.0/0"
  done <<< "$ALL_OPEN"
else
  pass "No security groups allow all traffic from 0.0.0.0/0"
fi

# ─── 4. Instance Roles — Admin Access ─────────────────────────────────────────
header "4. EC2 Instance Roles — Over-Privileged"

$AWS ec2 describe-instances \
  --filters "Name=instance-state-name,Values=running" \
  --query 'Reservations[*].Instances[*].[InstanceId,IamInstanceProfile.Arn,Tags[?Key==`Name`].Value|[0]]' \
  --output text 2>/dev/null | while IFS=$'\t' read -r instance_id profile_arn name; do
  [[ -z "$profile_arn" || "$profile_arn" == "None" ]] && continue
  name="${name:-unnamed}"

  # Extract profile name from ARN
  profile_name=$(echo "$profile_arn" | cut -d'/' -f2)

  # Get role name from profile
  role_name=$($AWS iam get-instance-profile \
    --instance-profile-name "$profile_name" \
    --query 'InstanceProfile.Roles[0].RoleName' --output text 2>/dev/null || echo "")

  [[ -z "$role_name" || "$role_name" == "None" ]] && continue

  # Check if AdministratorAccess is attached
  admin=$($AWS iam list-attached-role-policies --role-name "$role_name" \
    --query 'AttachedPolicies[?PolicyName==`AdministratorAccess`].PolicyName' \
    --output text 2>/dev/null || echo "")

  if [[ -n "$admin" ]]; then
    critical "Instance $instance_id ($name) has role $role_name with AdministratorAccess"
  else
    pass "Instance $instance_id ($name) role $role_name — no AdministratorAccess"
  fi
done

# ─── 5. SSM Agent — Session Manager Readiness ─────────────────────────────────
header "5. SSM Agent — Session Manager Availability"

SSM_INSTANCES=$($AWS ssm describe-instance-information \
  --query 'InstanceInformationList[*].[InstanceId,PingStatus,AgentVersion]' \
  --output text 2>/dev/null || echo "")

RUNNING_COUNT=$($AWS ec2 describe-instances \
  --filters "Name=instance-state-name,Values=running" \
  --query 'length(Reservations[*].Instances[*])' \
  --output text 2>/dev/null || echo "0")

SSM_COUNT=$(echo "$SSM_INSTANCES" | grep -c "Online" 2>/dev/null || echo "0")

if [[ $SSM_COUNT -eq 0 ]]; then
  warning "No instances have SSM Agent online — Session Manager not available"
else
  info "$SSM_COUNT/$RUNNING_COUNT running instances have SSM Agent online"
  [[ $SSM_COUNT -lt $RUNNING_COUNT ]] && \
    warning "Some instances missing SSM Agent — cannot use Session Manager for those"
fi

# ─── 6. EBS Encryption ────────────────────────────────────────────────────────
header "6. EBS Volume Encryption"

UNENCRYPTED=$($AWS ec2 describe-volumes \
  --filters "Name=encrypted,Values=false" \
  --query 'Volumes[*].[VolumeId,Size,State]' \
  --output text 2>/dev/null || echo "")

if [[ -n "$UNENCRYPTED" ]]; then
  while IFS=$'\t' read -r vol_id size state; do
    warning "EBS Volume $vol_id (${size}GB, $state) is NOT encrypted"
  done <<< "$UNENCRYPTED"
else
  pass "All EBS volumes are encrypted"
fi

# Check if EBS encryption by default is enabled
DEFAULT_ENC=$($AWS ec2 get-ebs-encryption-by-default \
  --query 'EbsEncryptionByDefault' --output text 2>/dev/null || echo "false")

[[ "$DEFAULT_ENC" == "true" ]] && pass "EBS encryption by default is enabled" \
  || warning "EBS encryption by default is DISABLED — new volumes won't be encrypted automatically"

# ─── Summary ──────────────────────────────────────────────────────────────────
header "Audit Summary"
echo -e "  ${RED}Critical issues: $CRITICAL_COUNT${RESET}"
echo -e "  ${YELLOW}Warnings:        $WARNING_COUNT${RESET}"

if [[ $CRITICAL_COUNT -gt 0 ]]; then
  echo -e "\n${RED}${BOLD}Action required — $CRITICAL_COUNT critical issue(s) found.${RESET}"
  exit 1
else
  echo -e "\n${GREEN}${BOLD}No critical issues found.${RESET}"
  exit 0
fi
