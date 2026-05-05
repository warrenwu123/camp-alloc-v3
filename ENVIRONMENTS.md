# Deployment Environments

## Overview

| Environment | Branch | URL | Trigger |
|---|---|---|---|
| **Production** | `gh-pages` | https://kmgcamp.github.io/camp-alloc-v2/ | Push to `main` |
| **PR Preview** | `gh-pages-previews/pr-N/` | https://kmgcamp.github.io/camp-alloc-v2/pr-N/ | Open/push to any PR |
| **Test suite** | same as above | `.../test.html` | Same as above |

---

## How It Works

### Every PR
1. Push a commit → `preview.yml` triggers automatically
2. Builds a patched `index.html` with correct base path
3. Deploys to `gh-pages-previews` branch under `pr-{N}/`
4. Bot posts a comment on the PR with the preview URL and test suite link
5. Every subsequent push updates the same preview URL
6. When PR is closed/merged → `cleanup.yml` removes the preview folder

### Merging to main
1. PR merged → `production.yml` triggers
2. Builds production `index.html`
3. Deploys to `gh-pages` branch (what GitHub Pages serves)
4. Live within ~1 minute

---

## GitHub Repository Setup

### 1. GitHub Pages source
Go to **Settings → Pages**:
- Source: **Deploy from a branch**
- Branch: **`gh-pages`** / `/ (root)`

### 2. Required Secrets
Go to **Settings → Secrets and variables → Actions**:

| Secret | Value | Used by |
|---|---|---|
| `PRODUCTION_WORKER_URL` | `https://campbook2.alvinkc.workers.dev` | production.yml |
| `STAGING_WORKER_URL` | `https://campbook2-staging.alvinkc.workers.dev` *(or same as prod)* | preview.yml |

> If `STAGING_WORKER_URL` is not set, previews fall back to the production worker URL.

### 3. Required Permissions
Go to **Settings → Actions → General → Workflow permissions**:
- Select **"Read and write permissions"**
- Check **"Allow GitHub Actions to create and approve pull requests"**

---

## PR Workflow (step by step)

```
1.  git checkout -b feature/my-feature
2.  # make changes
3.  git push origin feature/my-feature
4.  # open PR on GitHub
5.  ↓ GitHub Actions runs preview.yml
6.  ↓ Bot comments: "Preview Ready → https://...github.io/.../pr-42/"
7.  # test the preview URL
8.  # push more commits → preview auto-updates
9.  # approve & merge PR
10. ↓ GitHub Actions runs production.yml → production updated
11. ↓ GitHub Actions runs cleanup.yml → preview folder deleted
```

---

## Worker Environments

For a true staging setup (isolated data), deploy a second Cloudflare Worker:

```bash
# In backend/ directory
wrangler deploy --env staging
```

Add to `backend/wrangler.toml`:
```toml
[env.staging]
name = "campbook2-staging"

[[env.staging.d1_databases]]
binding       = "DB"
database_name = "camp-alloc-db-staging"
database_id   = "YOUR_STAGING_DB_ID"
```

Set `STAGING_WORKER_URL` secret to `https://campbook2-staging.alvinkc.workers.dev`.
