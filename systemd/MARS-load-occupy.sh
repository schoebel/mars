#!/bin/bash

# This is a trivial script for testing.
#
# It just occupies the mount point for some time,
# simulating a badly terminating process so that umount
# cannot work immediately, but needs to be restarted
# somewhat later.
#
# When this script is killed from "systemctl stop", the
# "sleep" sub-process will _not_ be killed, but terminate
# a little bit later. This leads to a race condition with lsof,
# similar to some observed practical daemon behaviour.

cd "$1" || exit $?

while true; do
	sleep 1
done
