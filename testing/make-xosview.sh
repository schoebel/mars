#!/bin/bash
#
# make xosoview ...

if [ "$1" = "" ]; then
	echo "Host unknown ...."
	echo "(use short hostname bap2/bs1/lxa2 ...)"
	exit
fi

SHST=`echo "$1"|sed -e 's!.*-!!'`
while true; do ssh -X $1 xosview -title $SHST -int; sleep 2; done