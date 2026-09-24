#!/bin/bash
# Keep the hosted walletd running.
#
# It had no supervisor: it was started with `setsid nohup` and nothing watched it. When
# the OOM killer took it at 2026-09-24 10:20:35 (anon-rss 54.7 GB of a 62 GB box) it
# simply stayed dead for 48 minutes until someone looked. A crash must cost seconds, not
# however long it takes a human to notice.
#
# Self-detaches so it can be launched over ssh, then respawns the daemon whenever it
# exits, with a short backoff so a boot-loop cannot spin the box.
set -u
BIN=/root/zkas/bin/zkas-walletd
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

# Trial decryption stays on the CPU: measured 2026-09-23, the device path's MEDIAN was
# 8948 us/action against 211.9 for the CPU. See the submit gate in zkas-gpu.
export ZKAS_GPU=off

# Memory. Each in-flight subtree build snapshots that wallet's decoded leaves (~340 MB at
# 10.5M leaves), and with the root-gate bug fixed far more builds now run to completion
# instead of being thrown away — so the concurrency that was survivable while they all
# failed is not survivable now that they work. One build at a time, and a free-memory
# floor with real headroom above the largest wallet.
FLAGS="--network mainnet --rpc-server 127.0.0.1:16810 --listen 0.0.0.0:8501 --allow-remote \
--wallet-dir /root/firecash/wallets --allow-origin https://wallet.zkas.info --allow-origin https://wallet.firecash.info \
--allow-origin https://localhost --allow-origin capacitor://localhost --allow-default-token --runtime-threads 32 \
--proof-threads 3 --max-concurrent-proves 6 --sync-wallets 28 --sync-wallet-memory-mb 384 --load-wallets 16 \
--warm-wallets 1 --page-decode-threads 12 --page-cache-entries 768 --page-cache-ttl 90 --active-sync-window 1800 \
--idle-evict 2100 --max-resident-wallets 64 --subtree-free-floor-mb 12000 --warm-always 16 --warm-budget 60"

backoff=2
while true; do
  echo "$(date -Is) starting walletd"
  started=$(date +%s)
  $BIN $FLAGS 2>&1 | tee -a "$LOG"
  rc=${PIPESTATUS[0]}
  ran=$(( $(date +%s) - started ))
  echo "$(date -Is) walletd exited rc=$rc after ${ran}s"
  # A daemon that ran a while is a crash to recover from; one that dies instantly is a
  # bad binary or bad flags, and hammering it helps nobody.
  if [ "$ran" -gt 60 ]; then backoff=2; else backoff=$(( backoff * 2 )); [ "$backoff" -gt 120 ] && backoff=120; fi
  echo "$(date -Is) respawning in ${backoff}s"
  sleep "$backoff"
done
