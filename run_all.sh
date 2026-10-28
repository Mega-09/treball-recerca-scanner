#!/usr/bin/env bash
#
# Starts every server of the research project:
#   - 3 vulnerable test sites     (5001 supermarket, 5002 clinic, 5003 company)
#   - 3 secure test sites         (5011, 5012, 5013)  [TR_SECURE=1]
#   - fake PHP server (PHP2Shell) (5090)
#   - scanner web UI              (8080)  -> the one exposed through Cloudflare
#
# Meant to run under systemd (user service tr-scanner.service).
# If any server dies, the script exits with an error and systemd restarts the
# whole set (Restart=always).
set -u

PY=/home/debian/treball_recerca/scanner/venv/bin/python
ROOT=/home/debian/treball_recerca

# Vulnerable test sites
( cd "$ROOT/testsites/supermercat" && exec env PORT=5001 "$PY" app.py ) &
( cd "$ROOT/testsites/hospital"    && exec env PORT=5002 "$PY" app.py ) &
( cd "$ROOT/testsites/empresa"     && exec env PORT=5003 "$PY" app.py ) &

# Secure test sites (every fix applied)
( cd "$ROOT/testsites/supermercat" && exec env TR_SECURE=1 PORT=5011 "$PY" app.py ) &
( cd "$ROOT/testsites/hospital"    && exec env TR_SECURE=1 PORT=5012 "$PY" app.py ) &
( cd "$ROOT/testsites/empresa"     && exec env TR_SECURE=1 PORT=5013 "$PY" app.py ) &

# Fake PHP server for the PHP2Shell demo
( cd "$ROOT/scanner/tools" && exec "$PY" mock_php.py ) &

# Scanner web UI
( cd "$ROOT/scanner" && exec "$PY" webapp.py ) &

# Wait until ANY server exits, then exit with an error so systemd restarts
# the whole set cleanly.
wait -n
echo "[run_all] a server exited; exiting 1 so systemd restarts everything." >&2
exit 1
