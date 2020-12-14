#!/bin/bash

# This is a trivial script for testing.

# Important: set pwd to occupy the mountpoint.
cd "$1" || exit $?

# 2-edge handshake protocol
start_flag=run-the-load.flag
running_flag=load-is-running.flag

if ! [[ -e $start_flag ]]; then
    exit 0
fi

rm -f $start_flag

while [[ -e $running_flag ]]; do
    sleep 1
done

exit 0
