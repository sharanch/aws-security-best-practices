# OIDC Authentication for CI/CD — No Static Keys

## The Problem

Storing `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` in GitHub Secrets or GitLab CI variables means you have permanent credentials sitting in your CI platform. If the platform is breached, or someone with repo access accidentally logs them, they're compromised.

---

## How OIDC Works for CI/CD

```
GitHub Actions runner starts
        │
        ▼
GitHub generates a short-lived OIDC token (JWT) for this specific job
        │
        ▼
Job sends OIDC token to AWS STS: AssumeRoleWithWebIdentity
        │
        ▼
STS validates token with GitHub's OIDC provider
        │
        ▼
STS returns temporary credentials (valid for job duration only)
        │
        ▼
Job uses credentials — they expire when the job ends
        │
        ▼
No static keys stored anywhere
```

---

## Setup — GitHub Actions with AWS OIDC

### Step 1 — Create OIDC Identity Provider in AWS
```bash
# Add GitHub as a trusted OIDC provider
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com \
  --client-id-list sts.amazonaws.com \
  --thumbprint-list 6938fd4d98bab03faadb97b34396831e3780aea1

# Verify it was created
aws iam list-open-id-connect-providers
```

### Step 2 — Create IAM Role for GitHub Actions
```bash
# Create the role with a trust policy scoped to your specific repo
aws iam create-role \
  --role-name GitHubActionsDeployRole \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:sharanch/my-app:*"
        }
      }
    }]
  }'

# Attach only the permissions the pipeline actually needs
aws iam attach-role-policy \
  --role-name GitHubActionsDeployRole \
  --policy-arn arn:aws:iam::aws:policy/AmazonECRContainerRegistryFullAccess

# Scope further — only push to specific ECR repo
aws iam put-role-policy \
  --role-name GitHubActionsDeployRole \
  --policy-name ECRPushOnly \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": [
        "ecr:GetAuthorizationToken",
        "ecr:BatchCheckLayerAvailability",
        "ecr:PutImage",
        "ecr:InitiateLayerUpload",
        "ecr:UploadLayerPart",
        "ecr:CompleteLayerUpload"
      ],
      "Resource": "arn:aws:ecr:ap-south-1:123456789:repository/my-app"
    },
    {
      "Effect": "Allow",
      "Action": "ecr:GetAuthorizationToken",
      "Resource": "*"
    }]
  }'
```

### Step 3 — Use in GitHub Actions Workflow
```yaml
# .github/workflows/deploy.yml
name: Deploy

on:
  push:
    branches: [main]

permissions:
  id-token: write   # Required for OIDC
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Configure AWS credentials via OIDC
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/GitHubActionsDeployRole
          aws-region: ap-south-1
          # No AWS_ACCESS_KEY_ID or AWS_SECRET_ACCESS_KEY needed

      - name: Verify identity
        run: aws sts get-caller-identity

      - name: Build and push to ECR
        run: |
          aws ecr get-login-password | docker login --username AWS \
            --password-stdin 123456789012.dkr.ecr.ap-south-1.amazonaws.com
          docker build -t my-app .
          docker push 123456789012.dkr.ecr.ap-south-1.amazonaws.com/my-app:${{ github.sha }}
```

---

## Setup — GitLab CI with AWS OIDC

```bash
# Trust policy for GitLab
aws iam create-role \
  --role-name GitLabCIDeployRole \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/gitlab.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "gitlab.com:aud": "https://gitlab.com"
        },
        "StringLike": {
          "gitlab.com:sub": "project_path:sharanch/my-project:ref_type:branch:ref:main"
        }
      }
    }]
  }'
```

```yaml
# .gitlab-ci.yml
deploy:
  image: amazon/aws-cli
  script:
    - >
      export $(printf "AWS_ACCESS_KEY_ID=%s AWS_SECRET_ACCESS_KEY=%s AWS_SESSION_TOKEN=%s"
      $(aws sts assume-role-with-web-identity
      --role-arn arn:aws:iam::123456789012:role/GitLabCIDeployRole
      --role-session-name gitlab-ci
      --web-identity-token $CI_JOB_JWT_V2
      --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]'
      --output text))
    - aws sts get-caller-identity
```

---

## Scope Trust to Specific Branches/Events

```bash
# Only allow main branch to assume the production deploy role
"StringEquals": {
  "token.actions.githubusercontent.com:sub": "repo:sharanch/my-app:ref:refs/heads/main"
}

# Allow any branch to assume a read-only staging role
"StringLike": {
  "token.actions.githubusercontent.com:sub": "repo:sharanch/my-app:*"
}

# Only allow specific environments
"StringEquals": {
  "token.actions.githubusercontent.com:sub": "repo:sharanch/my-app:environment:production"
}
```

---

## Checklist

- [ ] GitHub/GitLab OIDC provider added to AWS IAM
- [ ] No `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` in CI platform secrets
- [ ] IAM roles scoped per environment (dev/staging/prod separate roles)
- [ ] Trust policy scoped to specific repo and branch — not `repo:org/*:*`
- [ ] Deployment roles have minimum permissions for their job
- [ ] `id-token: write` permission set in GitHub Actions workflow
