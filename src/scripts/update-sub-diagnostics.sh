#!/usr/bin/env bash
set -euo pipefail

# Resolve repository root robustly. Prefer git, fallback to parent of parent of this script (since we're under src/scripts).
if command -v git >/dev/null 2>&1; then
  REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
fi
if [[ -z "${REPO_ROOT:-}" ]]; then
  _SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
  REPO_ROOT="$(cd "${_SCRIPT_DIR}/../.." && pwd)"
fi

pushd "$REPO_ROOT/src/diagnostics" >/dev/null
git fetch origin
if ! git diff --quiet origin/main; then
  echo "Upstream changes detected. Updating..."
  git merge origin/main  # Or: git rebase origin/main
  git rev-parse --short HEAD >/dev/null || true
  SHORT="$(git rev-parse --short HEAD || echo unknown)"
  popd >/dev/null
  pushd "$REPO_ROOT" >/dev/null
  git add src/diagnostics
  git commit -m "Update submodule to latest main (${SHORT})" || echo "Nothing to commit"
  popd >/dev/null
else
  echo "No upstream changes. Skipping."
  popd >/dev/null
fi