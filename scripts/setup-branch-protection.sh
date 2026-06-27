#!/usr/bin/env bash
set -euo pipefail

repo="${GITHUB_REPOSITORY:-$(gh repo view --json nameWithOwner -q .nameWithOwner)}"
branch="${PROTECTED_BRANCH:-master}"
config="${BRANCH_PROTECTION_CONFIG:-ci/branch-protection.json}"

if [[ ! -f "${config}" ]]; then
  echo "branch protection config not found: ${config}" >&2
  exit 1
fi

gh api \
  --method PUT \
  -H "Accept: application/vnd.github+json" \
  "/repos/${repo}/branches/${branch}/protection" \
  --input "${config}"

echo "Branch protection applied to ${repo}:${branch} (requires Test / build and Test / test status checks)"
