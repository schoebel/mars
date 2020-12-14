#!/bin/bash

# This is a trivial script for testing.
#
# Beside some trivial dd write load generator,
# it may occupy the mount point for some time,
# simulating a badly terminating process so that umount
# cannot work immediately, but needs to be restarted
# somewhat later.
#
# When this script is killed from "systemctl stop", the
# "sleep" sub-process will _not_ be killed, but terminate
# a little bit later. This leads to a race condition with lsof,
# similar to some observed practical daemon behaviour.

# Important: set pwd to occupy the mountpoint, also for sub-processes
cd "$1" || exit $?

# End writing after a while => allow for reaching UpToDate
nr_load="${2:-5}"

# 2-edge handshake protocol
start_flag=run-the-load.flag
running_flag=load-is-running.flag

if [[ -e $start_flag ]]; then
    exit 0
fi

: > $start_flag
: > $running_flag

{
    testfile=dummy-testfile.zero

    while [[ -e $start_flag ]] && [[ -e $running_flag ]]; do
    # do not write too much, for reasonable testing of KASAN kernels
	if (( nr_load-- > 0 )); then
	    dd if=/dev/zero of=$testfile bs=1k count=1001
	else
	    touch $testfile
	fi
	sleep $(( RANDOM * 5 / 32767 )) &
	wait
    done

    rm -f $running_flag
} &

exit 0
