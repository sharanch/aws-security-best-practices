# Deploying to GitHub Pages with a Custom Subdomain

This guide walks through hosting this project at a custom subdomain like
`security.sharanch.dev` using GitHub Pages + Cloudflare DNS.

---

## Step 1 — Push the Repo to GitHub

```bash
git init
git add .
git commit -m "feat: aws security best practices + portfolio site"
gh repo create aws-security-best-practices --public --push --source .
```

---

## Step 2 — Enable GitHub Pages

1. Go to your repo on GitHub
2. **Settings → Pages**
3. Under **Source**, select **GitHub Actions**
4. The workflow in `.github/workflows/deploy.yml` will trigger automatically on push

---

## Step 3 — Choose Your Subdomain and Update CNAME

Edit the `CNAME` file in the repo root — replace the placeholder with your chosen subdomain:

```bash
# Example
echo "security.sharanch.dev" > CNAME
git add CNAME && git commit -m "chore: set custom domain" && git push
```

Options:
- `security.sharanch.dev`
- `aws-security.sharanch.dev`
- `labs.sharanch.dev`

---

## Step 4 — Add DNS Record in Cloudflare

1. Log in to Cloudflare → your `sharanch.dev` zone
2. **DNS → Add record**

| Field   | Value                        |
|---------|------------------------------|
| Type    | `CNAME`                      |
| Name    | `security` (your subdomain)  |
| Target  | `sharanch.github.io`         |
| Proxy   | **DNS only** (grey cloud) ⚠️ |

> **Important:** Proxy must be **off** (grey cloud). GitHub Pages handles TLS itself
> and Cloudflare proxying breaks the certificate provisioning.

---

## Step 5 — Set Custom Domain in GitHub Pages Settings

1. Go to **Settings → Pages → Custom domain**
2. Enter your subdomain: `security.sharanch.dev`
3. Click **Save**
4. Wait ~2 minutes for GitHub to provision the TLS certificate
5. Enable **Enforce HTTPS** once the cert is issued

---

## Verification

```bash
# Check DNS propagation
dig security.sharanch.dev CNAME

# Should return:
# security.sharanch.dev. → sharanch.github.io.

# Check the site is live
curl -I https://security.sharanch.dev
# HTTP/2 200
```

---

## Auto-Deploy

Every push to `main` triggers the GitHub Actions workflow and redeploys the site.
The workflow uses OIDC (no static tokens) and pins all actions to commit SHAs.

```
git push origin main
# → GitHub Actions triggers
# → Site live at your subdomain in ~30 seconds
```
