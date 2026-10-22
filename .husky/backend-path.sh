# Sourced by the hooks in this folder (cwd is the repo root).
# Put the backend's virtualenv first on PATH so ruff/mypy/python resolve to the project's pinned versions.
for venv in backend/.venv backend/venv; do
  if [ -x "$venv/bin/python" ]; then
    PATH="$PWD/$venv/bin:$PATH"
    export PATH
    break
  fi
done
