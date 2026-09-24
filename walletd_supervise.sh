#!/bin/bash
# Keep the hosted walletd running.
#
# It had no supervisor at all: started with `setsid nohup`, nothing watching. When the OOM
# killer took it on 2026-09-24 at 10:20:35 it stayed dead 48 minutes until a human looked.
#
# Flags live in walletd.flags and are re-read before EVERY spawn. That matters: the only
# reason to restart a supervisor was to change a knob, and doing that meant a second
# supervisor spawning a second daemon while the first still drained for ~15 minutes —
# two multi-gigabyte processes at once, which took the box to 1 GB free. Now a knob change
# is: edit the file, SIGTERM the daemon, done. One daemon, ever.
set -u
BIN=/root/zkas/bin/zkas-walletd
FLAGS_FILE=/root/zkas/walletd.flags
LOG=/root/zkas/walletd.log
SUP=/root/zkas/supervisor.log
PIDFILE=/root/zkas/supervisor.pid

if [ "${ZKAS_SUP_DETACHED:-0}" != "1" ]; then
  export ZKAS_SUP_DETACHED=1
  setsid nohup "$0" "$@" >/dev/null 2>&1 </dev/null &
  echo "supervisor started (pid $!); log: $SUP"
  exit 0
fi

echo $$ > "$PIDFILE"
exec >>"$SUP" 2>&1

backoff=2
while true; do
  # shellcheck disable=SC1090
  . "$FLAGS_FILE"
  export ZKAS_GPU
  echo "$(date -Is) starting walletd"
  started=$(date +%s)
  # shellcheck disable=SC2086
  $BIN $WALLETD_FLAGS 2>&1 | tee -a "$LOG"
  rc=${PIPESTATUS[0]}
  ran=$(( $(date +%s) - started ))
  echo "$(date -Is) walletd exited rc=$rc after ${ran}s"
  # A daemon that ran a while is a crash to recover from; one that dies instantly is a bad
  # binary or bad flags, and hammering it helps nobody.
  if [ "$ran" -gt 60 ]; then backoff=2; else backoff=$(( backoff * 2 )); [ "$backoff" -gt 120 ] && backoff=120; fi
  echo "$(date -Is) respawning in ${backoff}s"
  sleep "$backoff"
done
