pushd /workspaces/gdbsos/src/diagnostics
git fetch origin
if ! git diff --quiet origin/main; then
  echo "Upstream changes detected. Updating..."
  git merge origin/main  # Or: git rebase origin/main
  pushd /workspaces/gdbsos
  git add src/diagnostics
  git commit -m "Update submodule to latest main ($(git -C src/diagnostics rev-parse --short HEAD))"
  popd
else
  echo "No upstream changes. Skipping."
fi
popd