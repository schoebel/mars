#!/bin/bash
set -Eeuo pipefail
export PATH=/usr/bin:/bin:/sbin LC_ALL=C
mount -t devtmpfs devtmpfs /dev
exec >/dev/console 2>&1
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t tmpfs tmpfs /run
fail() {
    echo "MARS_QEMU_FAIL line=$1"
    ls -l /dev /dev/mars /sys/block || true
    cat /proc/sys/mars/info || true
    dmesg || true
    find /mars -maxdepth 3 -type l -printf '%p -> %l\n' || true
    poweroff
}
trap 'fail "$LINENO"' ERR
hostname mars-test
echo "MARS_QEMU_KERNEL $(uname -r)"
modprobe virtio_mmio
modprobe virtio_blk
modprobe virtio_net
modprobe ext4
ip link set lo up
iface=$(ls /sys/class/net | grep -v '^lo$' | head -1)
ip link set "$iface" up
ip addr add 10.0.2.15/24 dev "$iface"
for i in {1..50}; do [ -b /dev/vdb ] && break; sleep .1; done
mkfs.ext4 -q -F /dev/vda
mount /dev/vda /mars
chmod 0700 /mars
marsadm create-cluster
modprobe mars
cat /proc/sys/mars/version
cat /proc/sys/mars/lamport_clock
marsadm create-resource test /dev/vdb
mkdir -p /dev/mars
for i in {1..60}; do
    if [ -b '/dev/mars!test' ] && [ ! -e /dev/mars/test ]; then
        ln -s '../mars!test' /dev/mars/test
    fi
    [ -b /dev/mars/test ] && break
    sleep 1
done
ls -l /dev/mars /sys/block
test -b /dev/mars/test
chmod 0600 /dev/mars/test
test "$(blockdev --getsize64 /dev/mars/test)" = 134217728
dd if=/dev/urandom of=/tmp/pattern bs=4096 count=256 status=none
dd if=/tmp/pattern of=/dev/mars/test bs=4096 conv=fsync status=none
dd if=/dev/mars/test of=/tmp/readback bs=4096 count=256 iflag=direct status=none
cmp /tmp/pattern /tmp/readback
for i in {1..30}; do
    [ "$(readlink /mars/resource-test/actual-mars-test/open-count)" = 0 ] && break
    sleep 1
done
timeout 90 marsadm secondary test
timeout 90 marsadm down test
rmmod mars
dd if=/dev/vdb of=/tmp/backing bs=4096 count=256 iflag=direct status=none
cmp /tmp/pattern /tmp/backing
echo MARS_QEMU_BLOCK_PASS
modprobe mars
cat /proc/sys/mars/version
timeout 90 marsadm attach test
timeout 90 marsadm resume-fetch-local test
timeout 90 marsadm resume-replay-local test
timeout 90 marsadm primary test
for i in {1..60}; do [ -b /dev/mars/test ] && break; sleep 1; done
test -b /dev/mars/test
chmod 0600 /dev/mars/test
mkfs.ext4 -q -F -E nodiscard /dev/mars/test
mount /dev/mars/test /mnt
dd if=/tmp/pattern of=/mnt/pattern bs=1M conv=fsync status=none
cmp /tmp/pattern /mnt/pattern
umount /mnt
for i in {1..30}; do
    [ "$(readlink /mars/resource-test/actual-mars-test/open-count)" = 0 ] && break
    sleep 1
done
timeout 90 marsadm secondary test
timeout 90 marsadm down test
rmmod mars
mount -o ro,noload /dev/vdb /mnt
cmp /tmp/pattern /mnt/pattern
umount /mnt
echo MARS_QEMU_FILESYSTEM_PASS
echo MARS_QEMU_PASS
poweroff
