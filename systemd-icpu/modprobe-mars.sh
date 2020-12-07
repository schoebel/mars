#!/bin/bash

# do no longer start any systemd-controlled resources via nodeagent init

for res in $(
    marsadm get-systemd-unit all |\
	grep "^nodeagent" |\
	awk '{ print $1; }' |\
	sed 's/nodeagent-//' |\
	cut -d. -f1 |\
	sed 's/\\x2d/-/g'
); do
  # workaround "nodeagent status --target"
  nodeagent stop $res || echo ignore the error
done

modprobe mars
rc=$?

sleep 3
marsadm systemd-trigger

exit $rc
