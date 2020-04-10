#! /usr/bin/env bash
SCRIPTPATH="$( cd "$(dirname "$0")" || exit ; pwd -P )"
if [ ! -f $SCRIPTPATH/ubirch-client-go ]; then
  echo "Missing 'ubirch-client-go' program file"
  exit 1
fi
if [ ! -f $SCRIPTPATH/config.json ]; then
  echo "Missing 'config.json' configurations file"
  exit 1
fi

while (true); do
  $SCRIPTPATH/ubirch-client-go
  echo "Press Ctrl-C to stop!"
  sleep 5
done
