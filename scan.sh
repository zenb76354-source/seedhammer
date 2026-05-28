#!/bin/bash
# seedscan — multi-line script for RunPod terminal
# Usage: ./seedscan.sh H 1288834970 1288840000
# Kills all, generates + verifies in one pipe, no disk storage for keys

MODE=${1:-H}
TS_START=${2:-1288834970}
TS_END=${3:-1288840000}

pkill -9 seedhammer 2>/dev/null
pkill -9 vaultwatch-cuda 2>/dev/null
sleep 1

cd /vaultwatch
/seedhammer/seedhammer "$MODE" \
  --ts-start "$TS_START" \
  --ts-end "$TS_END" \
  --output /dev/stdout 2>/dev/null | \
./vaultwatch-cuda 2>/dev/null
