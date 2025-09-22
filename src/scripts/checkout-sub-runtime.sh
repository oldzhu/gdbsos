#!/usr/bin/env bash
set -euo pipefail

# Checkout a branch/tag in the src/runtime submodule/clone with an interactive menu
# - Shows main and release/x.y branches from origin
# - Allows typing a tag/ref (e.g., v8.0.6) directly
#
# Usage:
#   src/scripts/checkout-sub-runtime.sh

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Determine repository root via git, independent of the script's folder location.
# Allow override via environment variable REPOROOT if provided.
REPOROOT="${REPOROOT:-}"
if [[ -z "${REPOROOT}" ]]; then
  REPOROOT="$(git -C "${script_dir}" rev-parse --show-toplevel 2>/dev/null || true)"
fi
if [[ -z "${REPOROOT}" ]]; then
  echo "error: unable to determine repo root (git rev-parse --show-toplevel failed). Set REPOROOT env var." >&2
  exit 1
fi
RUNTIME_DIR="${REPOROOT}/src/runtime"

if [[ ! -d "${RUNTIME_DIR}" ]]; then
  echo "error: runtime directory not found: ${RUNTIME_DIR}" >&2
  exit 1
fi

pushd "${RUNTIME_DIR}" >/dev/null

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "error: ${RUNTIME_DIR} is not a git repository" >&2
  popd >/dev/null
  exit 1
fi

if ! git remote get-url origin >/dev/null 2>&1; then
  echo "error: remote 'origin' is not configured in ${RUNTIME_DIR}" >&2
  popd >/dev/null
  exit 1
fi

echo "+ fetching branches and tags from origin..." >&2
# Fetch branches and tags (prune removed remote branches)
git fetch --prune origin '+refs/heads/*:refs/remotes/origin/*' --tags >/dev/null

# Build menu options: include 'main' if exists, plus release/x.y branches
options=()
if git ls-remote --heads origin main >/dev/null 2>&1; then
  options+=("main")
fi
# Collect release/x.y branches from origin
mapfile -t release_branches < <(git ls-remote --heads origin 'release/[0-9]*.[0-9]*' \
  | awk '{print $2}' \
  | sed -E 's#^refs/heads/##' \
  | sort -t'/' -k2,2V)

if (( ${#release_branches[@]} > 0 )); then
  options+=("${release_branches[@]}")
fi

if (( ${#options[@]} == 0 )); then
  echo "warning: no 'main' or 'release/x.y' branches found on origin." >&2
  echo "You can still enter a tag/ref manually (e.g., v8.0.6)."
fi

# Print menu
if (( ${#options[@]} > 0 )); then
  echo "Select a branch to checkout (or type a tag/ref like v8.0.6)." >&2
  for i in "${!options[@]}"; do
    printf "%2d) %s\n" "$((i+1))" "${options[$i]}"
  done
fi

read -rp "> Enter number 1..${#options[@]}, or a ref (v8.0.6), or 'q' to quit: " choice
choice_trimmed="${choice:-}"
choice_trimmed="${choice_trimmed//[$'\t\r\n ']}"

if [[ -z "${choice_trimmed}" || "${choice_trimmed}" == "q" || "${choice_trimmed}" == "Q" ]]; then
  echo "Aborted."
  popd >/dev/null
  exit 0
fi

is_number='^[0-9]+$'
if [[ "${choice_trimmed}" =~ ${is_number} ]] && (( choice_trimmed >= 1 )) && (( choice_trimmed <= ${#options[@]} )); then
  ref="${options[$((choice_trimmed-1))]}"
  # Map to remote branch and local branch name
  if [[ "${ref}" == "main" ]]; then
    remote_ref="origin/main"
    local_branch="main"
  else
    remote_ref="origin/${ref}"
    local_branch="${ref}"
  fi
  echo "+ checking out ${local_branch} tracking ${remote_ref}"
  # Create/update local branch to point at remote and set upstream
  git checkout -B "${local_branch}" "${remote_ref}"
  git branch --set-upstream-to="${remote_ref}" "${local_branch}" >/dev/null 2>&1 || true
  display_ref="${local_branch}"
else
  # Treat input as a ref/tag name directly
  ref="${choice_trimmed}"
  echo "+ checking out ${ref}"
  git checkout "${ref}"
  display_ref="${ref}"
fi

runtime_head="$(git rev-parse --short HEAD 2>/dev/null || true)"

popd >/dev/null

# Offer to commit the updated submodule pointer in the superproject
echo
read -rp "> Commit submodule update in superproject now? [y/N]: " _ans
_ans_lc="${_ans,,}"
if [[ "${_ans_lc}" == "y" || "${_ans_lc}" == "yes" ]]; then
  default_msg="Move runtime submodule to ${display_ref}${runtime_head:+ (${runtime_head})}"
  read -rp "> Commit message [${default_msg}]: " _msg
  commit_msg="${_msg:-$default_msg}"
  # Stage the submodule pointer change and commit if there is a diff
  if git -C "${REPOROOT}" diff --quiet --exit-code -- "src/runtime"; then
    echo "No changes to commit in superproject (src/runtime is unchanged)."
  else
    git -C "${REPOROOT}" add "src/runtime"
    git -C "${REPOROOT}" commit -m "${commit_msg}"
    echo "+ committed: ${commit_msg}"
  fi
fi

echo "Done."
