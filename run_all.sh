#!/usr/bin/env bash
# Run every collector and write JSON into ./output
#   sudo ./run_all.sh "$(which python)"          # full coverage (recommended)
#   sudo ./run_all.sh "$(which python)" --fast   # skip the slow checks
# Pass your venv's python explicitly: sudo resets PATH and would pick /usr/bin/python.
set -u
PY="${1:-python}"; shift || true
FAST=0; [ "${1:-}" = "--fast" ] && FAST=1
cd "$(dirname "$0")"; mkdir -p output

declare -A EXTRA=()
if [ "$FAST" = 1 ]; then
  EXTRA[processes]="--no-hidden-check"; EXTRA[packages]="--no-verify"; EXTRA[services]="--no-analyze"
fi
fail=0
for c in accounts filesystem processes services packages configs network logs kernel persistence; do
  printf '%-12s ' "$c"
  start=$(date +%s)
  if "$PY" -m "collectors.$c" --pretty ${EXTRA[$c]:-} > "output/.$c.tmp" 2> "output/.$c.err"; then
    mv "output/.$c.tmp" "output/$c.json"; echo "ok   ($(( $(date +%s) - start ))s)"
  else
    echo "FAILED  -> see output/.$c.err"; fail=1
  fi
done
printf '%-12s ' "engine"
if "$PY" -m engine --output output > output/.engine.txt 2>&1; then head -1 output/.engine.txt; else echo "FAILED -> see output/.engine.txt"; fail=1; fi
printf '%-12s ' "history/ml"
if "$PY" -m ml run --output output > output/.ml.txt 2>&1; then head -1 output/.ml.txt; else echo "not recorded -> $(head -1 output/.ml.txt)"; fi
# JSON written by root must stay readable/overwritable by the dashboard user
if [ -n "${SUDO_UID:-}" ]; then chown -R "$SUDO_UID:$SUDO_GID" output; fi
exit $fail
