#!/bin/bash

pid=$BASHPID
ppid=$PPID

echo -n L $* $(pstree $pid) > /proc/sys/mars/trigger

exec /usr/local/bin/marsadm systemd-trigger >> /mars/trigger.log 2>&1
