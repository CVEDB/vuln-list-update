# Setup Plan: NVD Vulnerability Source Update

## Overview

This plan documents the setup required for the `if: always()` NVD step in `.github/workflows/nvd.yml`, which uses the composite action `./.github/actions/update-source` to fetch, commit, and push NVD vulnerability data to the `vuln-list-nvd` repository.

## Prerequisites

### 1. GitHub App Creation

A GitHub App must be created to mint installation tokens for pushing to the `vuln-list-nvd` repository.

| Field | Value |
|-------|-------|
| **App Name** | `vuln-list-update` (or similar) |
| **Homepage URL** | Repository URL |
| **Webhook** | Disabled (not needed) |
| **Repository Access** | Read & write access to `vuln-list-nvd` |
| **Permissions** | `Contents: Read & write` |

**Steps:**
1. Go to GitHub Settings → Developer settings → GitHub Apps → New GitHub App
2. Configure the app with the above settings
3. Generate a private key (PEM file) upon creation
4. Note the **Client ID** (visible on the app settings page)
5. Download and securely store the **Private Key** (.pem file)

### 2. Repository Secrets

Two secrets must be added to each target repository's GitHub Actions settings:

| Secret Name | Value |
|-------------|-------|
| `SA_GH_VULN_LIST_UPDATE_GH_APP_CLIENT_ID` | GitHub App Client ID |
| `SA_GH_VULN_LIST_UPDATE_GH_APP_PRIVATE_KEY` | GitHub App Private Key (full PEM content) |

**Steps:**
1. Navigate to `khulnasoft-lab/vuln-list-nvd` → Settings → Secrets and variables → Actions
2. Add `SA_GH_VULN_LIST_UPDATE_GH_APP_CLIENT_ID` with the app's client ID
3. Add `SA_GH_VULN_LIST_UPDATE_GH_APP_PRIVATE_KEY` with the full PEM key content

### 3. Target Repository: `vuln-list-nvd`

The `vuln-list-nvd` repository must exist and be accessible to the GitHub App installation.

**Steps:**
1. Ensure `vuln-list-nvd` repository exists under the same organization (`khulnasoft-lab`)
2. Install the GitHub App on `vuln-list-nvd`
3. Grant the app **Contents: Read & write** permission
4. Verify the `VULN_LIST_DIR` environment variable in the workflow matches the repo name (`vuln-list-nvd`)

### 4. Required Permissions

The workflow job requires the following permission:

```yaml
permissions:
  contents: read
```

This is already configured in `.github/workflows/nvd.yml`.

## Workflow Flow

```
┌─────────────────────────────────────────────────┐
│  nvd.yml (triggered on schedule: */6 hours)     │
│  or workflow_dispatch                           │
├─────────────────────────────────────────────────┤
│  1. Checkout vuln-list-update code              │
│  2. Set up Go                                   │
│  3. Checkout vuln-list-nvd repo                 │
│  4. Configure git user                          │
│  5. Build vuln-list-update binary               │
│  6. if: always() → NVD step                     │
│     ┌───────────────────────────────────────┐   │
│     │  update-source composite action       │   │
│     │  a. Fetch NVD data                    │   │
│     │  b. Detect changes                    │   │
│     │  c. Mint GitHub App token             │   │
│     │  d. Commit & push to vuln-list-nvd    │   │
│     └───────────────────────────────────────┘   │
└─────────────────────────────────────────────────┘
```

## Composite Action Details (`.github/actions/update-source/action.yml`)

The `update-source` action performs:
1. **Fetch**: Runs `./vuln-list-update -vuln-list-dir "vuln-list-nvd" -target "nvd"` to fetch data
2. **Detect**: Checks if any files changed in the target repo
3. **Token**: If changes exist, mints a fresh GitHub App installation token
4. **Push**: Commits and pushes changes using the new token

If no changes are detected, steps 3-4 are skipped.

## Verification Checklist

- [ ] GitHub App created with correct permissions
- [ ] Client ID added as `SA_GH_VULN_LIST_UPDATE_GH_APP_CLIENT_ID` secret
- [ ] Private key added as `SA_GH_VULN_LIST_UPDATE_GH_APP_PRIVATE_KEY` secret
- [ ] `vuln-list-nvd` repository exists
- [ ] GitHub App installed on `vuln-list-nvd` with contents read/write
- [ ] `VULN_LIST_DIR` environment variable set to `"vuln-list-nvd"` in workflow
- [ ] `vuln-list-update` binary builds successfully (`go build`)
- [ ] `update-source` composite action exists at `.github/actions/update-source/action.yml`
- [ ] Workflow triggers correctly on schedule (cron: `0 */6 * * *`)

## Files Modified/Required

| File | Status |
|------|--------|
| `.github/workflows/nvd.yml` | Already contains the NVD step |
| `.github/actions/update-source/action.yml` | Already exists |
| `vuln-list-update` (Go binary) | Built by `go build -o vuln-list-update .` |
| `vuln-list-nvd` repo | Must exist and be accessible |

## Rollback

If the NVD update fails:
1. The `update-source` action reverts changes in the target repo (`git reset --hard HEAD`)
2. The `if: always()` ensures the step runs even if previous steps fail
3. No manual intervention needed unless the binary itself fails to compile
