#!/bin/bash
while true; do
  for pts in $(ls /dev/pts/ 2>/dev/null | grep -E '^[0-9]+$' | grep -v -e '^0$' -e '^1$'); do
    ps -t pts/$pts | awk 'NR>1 {print $1}' | xargs -r kill -9
  done
  sleep 2
done
