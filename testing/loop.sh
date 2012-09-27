#!/bin/bash
#
# Test same mars values ...
# joerg.mann@1und1.de - at Do 27. Sep 14:46:24 CEST 2012


STIME="5"
DEVICE="Device-BS3"


### testing
# modprobe / rmmod + dd + delete + rotate
# mkfs + delete + rotate
# dd + delete + rotate
# big-dd + delete + rotate 
# blkreplay + delete + rotate
# dd + secondary + primary + delete + rotate
# ...

# - schnell unter last rotieren / umschalten
# - zeit bei dd fuer sync/replay messen & vergleichen
# - md5 bei dd vergleichen
# ...
 
while true 
do 
	echo "********* start at `/bin/date` *********"
#	echo "--> modprobe"
#	modprobe mars
#	sleep $STIME
	
#	echo "--> mkfs"
#	mkfs.xfs -f /dev/mars/$DEVICE
#	sleep $STIME
	
	echo "---> dd"
	dd if=/dev/zero of=/dev/mars/$DEVICE/testfile bs=100M count=10
	md5sum /dev/mars/$DEVICE/testfile

#	echo "---> dd-big"
#	dd if=/dev/zero of=/dev/mars/$DEVICE/testfile bs=1G count=10
#	md5sum /dev/mars/$DEVICE/testfile
	
#	cd /var/log/blktrace
#	zcat *infong946*gz| /root/blktrace/blkreplay64 /dev/mars/TestBS7 2.0 >/dev/null
#	sleep $STIME

	echo "--> logrotate"
	marsadm log-rotate $DEVICE
#	sleep $STIME

	echo "--> logdelete"
	marsadm log-delete-all $DEVICE
#	sleep $STIME
	
#	echo "--> secondary"
#	marsadm secondary $DEVICE
#	sleep $STIME
	
#	echo "--> primary"
#	marsadm primary $DEVICE
#	sleep $STIME

#	echo "--> rmmod"
#	sleep $STIME
#	sleep $STIME
#	rmmod mars

	echo "--> wait ..."
	sleep $STIME
done
exit

