#!/bin/bash
set -ue

# find a valid and unused port to listen on
PORT=0
while [ $PORT -le 1024 ]; do
  PORT=$RANDOM
  # is the port in use?
  used=`netstat -lnt | grep ":$PORT" | grep -v grep | wc -l`
  if [ $used = 1 ]; then
    # port in use, skip it
    PORT=0
  fi
done
echo $PORT

