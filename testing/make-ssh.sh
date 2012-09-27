#!/bin/bash
#
# login ...


if [ "$1" = "" ]; then
	echo "Host unknown ...."
	echo "(use short hostname bap2/bs1/lxa2 ...)"
	exit
fi

while true; do ssh -A $1; sleep 2; done