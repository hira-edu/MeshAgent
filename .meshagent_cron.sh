#!/bin/sh
DIR=/Users/umairliaquat/Documents/GitHub/MeshAgent
PID="$DIR/.meshagent.pid"
if [ -f "$PID" ]; then
  p=$(cat "$PID" 2>/dev/null)
  [ -n "$p" ] && kill -0 "$p" 2>/dev/null && exit 0
fi
cd "$DIR" && ./meshagent --installedByUser=0 --__daemon </dev/null >/dev/null 2>&1 &
echo $! > "$PID"
