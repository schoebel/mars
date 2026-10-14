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
    find /mars -maxdepth 4 -type l -printf '%p -> %l\n' || true
    poweroff
}
trap 'fail "$LINENO"' ERR
node=primary
case "$(cat /proc/cmdline)" in *mars_test_node=secondary*) node=secondary;; esac
hostname "$node"
echo "$node" >/etc/hostname
printf '127.0.0.1 localhost\n10.42.0.1 primary\n10.42.0.2 secondary\n' >/etc/hosts
echo "MARS_QEMU_KERNEL $(uname -r) node=$node"
modprobe virtio_mmio
modprobe virtio_blk
modprobe virtio_net
modprobe ext4
ip link set lo up
iface=$(ls /sys/class/net | grep -v '^lo$' | head -1)
ip link set "$iface" up
if [ "$node" = primary ]; then ip addr add 10.42.0.1/24 dev "$iface";
else ip addr add 10.42.0.2/24 dev "$iface"; fi
for i in {1..50}; do [ -b /dev/vdb ] && break; sleep .1; done
mkfs.ext4 -q -F /dev/vda
mount /dev/vda /mars
chmod 0700 /mars
marsadm create-cluster
# Bootstrap the isolated pair without an SSH/rsync control plane. The module
# is still unloaded, and all subsequent metadata/data transfers use MARS TCP.
ln -sfn qemu-replication-test /mars/uuid
ln -sfn 10.42.0.1 /mars/ips/ip-primary
ln -sfn 10.42.0.2 /mars/ips/ip-secondary
modprobe mars
perl -e 'print pack("N*", 0..262143)' >/tmp/pattern
if [ "$node" = primary ]; then
    marsadm create-resource test /dev/vdb
    for i in {1..60}; do [ -b /dev/mars/test ] && break; sleep 1; done
    test -b /dev/mars/test
    chmod 0600 /dev/mars/test
    # Let the secondary finish initial synchronization, then test log shipping.
    for i in {1..90}; do
        [ "$(readlink /mars/resource-test/syncstatus-secondary || true)" = 134217728 ] && break
        sleep 1
    done
    test "$(readlink /mars/resource-test/syncstatus-secondary)" = 134217728
    dd if=/tmp/pattern of=/dev/mars/test bs=4096 conv=fsync status=none
    dd if=/dev/mars/test of=/tmp/readback bs=4096 count=256 iflag=direct status=none
    cmp /tmp/pattern /tmp/readback
    timeout 60 marsadm log-rotate test
    echo MARS_QEMU_PRIMARY_WRITTEN
    # The host stops this VM only once the secondary has verified the data.
    sleep 180
    false
else
    # Nonmembers do not receive resource details until join-resource requests
    # them. Wait for cluster connectivity, then let marsadm fetch the resource.
    for i in {1..90}; do [ -L /mars/actual-primary/alive ] && break; sleep 1; done
    test -L /mars/actual-primary/alive
    timeout 90 marsadm join-resource test /dev/vdb
    for i in {1..120}; do
        dd if=/dev/vdb of=/tmp/readback bs=4096 count=256 iflag=direct status=none
        if cmp -s /tmp/pattern /tmp/readback; then
            echo MARS_QEMU_REPLICATION_PASS
            poweroff
        fi
        sleep 1
    done
    false
fi
