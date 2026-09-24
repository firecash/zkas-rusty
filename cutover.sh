#!/bin/bash
# Clean cutover: exactly one walletd alive at any moment.
#
# The previous pattern (start a second supervisor, then SIGTERM the old daemon) left two
# multi-gigabyte processes running while the first drained for ~15 minutes and drove the
# box to 1 GB free. This stops the supervisor FIRST so nothing respawns, waits for every
# daemon to actually exit, swaps the binary, and only then brings a supervisor back.
set -u
OUT=/root/zkas/cutover.out
if [ "${CUTOVER_DETACHED:-0}" != "1" ]; then
  export CUTOVER_DETACHED=1
  setsid nohup "$0" "$@" >/dev/null 2>&1 </dev/null &
  echo "cutover started (pid $!); watch $OUT"
  exit 0
fi
exec >"$OUT" 2>&1

NEW=/root/zkas/rk-perf/target/release/zkas-walletd
BIN=/root/zkas/bin/zkas-walletd

echo "== stopping the supervisor so nothing respawns =="
SUP=$(cat /root/zkas/supervisor.pid 2>/dev/null || true)
[ -n "${SUP:-}" ] && kill "$SUP" 2>/dev/null || true
sleep 1

echo "== signalling every live walletd =="
for pid in $(pgrep -f "^/root/zkas/bin/zkas-walletd" || true); do
  echo "  SIGTERM $pid"; kill -TERM "$pid" 2>/dev/null || true
done

echo "== waiting for them to exit (drains flush checkpoints; do not hurry it) =="
for i in $(seq 1 240); do
  alive=$(pgrep -cf "^/root/zkas/bin/zkas-walletd" || true)
  [ "${alive:-0}" = "0" ] && { echo "  all exited after $((i*10))s"; break; }
  sleep 10
done
alive=$(pgrep -cf "^/root/zkas/bin/zkas-walletd" || true)
if [ "${alive:-0}" != "0" ]; then
  echo "  STILL ALIVE after 2400s — not swapping, restarting supervisor on the old binary"
else
  echo "== swapping binary =="
  cp -f "$BIN" "$BIN.pre-cutover-$(date +%Y%m%d-%H%M%S)"
  cp -f "$NEW" "$BIN"
  ls -la "$BIN"
fi
free -g | head -2

echo "== starting supervisor (reads walletd.flags) =="
/root/zkas/walletd_supervise.sh

for i in $(seq 1 60); do
  code=$(curl -s -m 5 -o /dev/null -w "%{http_code}" http://127.0.0.1:8501/api/status 2>/dev/null || true)
  [ "$code" = "200" ] && { echo "== UP after ${i}x5s =="; break; }
  sleep 5
done
ss -ltnp 2>/dev/null | grep ":8501 " | grep -oE "pid=[0-9]+"
free -g | head -2
echo CUTOVER_DONE
