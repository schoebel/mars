#!/bin/bash
# Copyright 2010-2013 Frank Liepold /  1&1 Internet AG
#
# Email: frank.liepold@1und1.de
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

#####################################################################

## some helpers concerning mount points

function mount_umount
{
    local host=$1 dev=$2 mount_point=$3
    lib_vmsg "  umounting dev $dev from $mount_point on $host"
    lib_remote_idfile $host umount -f $mount_point
    return $?
}

function mount_mount
{
    [ $# -eq 4 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local host=$1 dev="$2" mount_point=$3 fs_type=$4
    lib_vmsg "  mounting dev $dev (type $fs_type) on $mount_point on $host"
    lib_remote_idfile $host mount -t $fs_type $dev $mount_point
    return $?
}

function mount_is_device_mounted
{
    [ $# -eq 3 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local host=$1 dev=$2 varname_mountpoint=$3 rc
    local mount_out devname_in_mounttab
    # in the mount table the device appears under the device mapper name 
    # /dev/mapper/...
    lib_vmsg "  checking whether $host:$dev is 'device mapped'"
    devname_in_mounttab=$(lv_config_get_dm_dev $host $dev)
    rc=$?
    if [ $rc -ne 0 ]; then
        devname_in_mounttab=$dev
    fi
    lib_vmsg "  checking whether $devname_in_mounttab is mounted on $host"
    mount_out=($(lib_remote_idfile $host "mount | grep '^$devname_in_mounttab on'"))
    rc=$?
    if [ $rc -eq 0 ]; then
        eval $varname_mountpoint=${mount_out[2]}
    fi
    return $rc
}

function mount_is_dir_mountpoint
{
    local host=$1 dir=$2 rc
    lib_vmsg "  checking whether $dir is a mountpoint on $host"
    lib_remote_idfile $host "mount | grep ' on $dir '"
    rc=$?
    return $rc
}

function mount_mount_data_device
{
    [ $# -eq 2 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local host=$1 res=$2
    local dev=$(resource_get_data_device $res)
    local mount_point=${resource_mount_point_list[$res]}

    lib_rw_remote_check_device_fs $host $dev ${resource_fs_type_list[$res]}
    lib_rw_mount_data_device $host $dev $mount_point
}

function mount_umount_data_device_all
{
    local res=${1:-${resource_name_list[0]}}
    local host
    for host in ${global_host_list[@]}; do 
        mount_umount_data_device $host $res
    done
}

function mount_umount_data_device
{
    local host=$1 res=$2
    local dev=$(resource_get_data_device $res)
    local mount_point=${resource_mount_point_list[$res]}
    if mount_is_dir_mountpoint $host $mount_point; then
        local maxwait=60 waited=0 rc
        while true;do
            mount_umount $host $dev $mount_point
            rc=$?
            if [ $rc -eq 0 ];then
                break
            fi
            sleep 1
            let waited+=1
            lib_vmsg "  waited $waited for unmounting $host:$mount_point"
            lib_vmsg "  printing linktree on $host"
            lib_linktree_print_linktree $host
            if [ $waited -eq $maxwait ]; then
                lib_exit 1 "maxwait $maxwait exceeded"
            fi
        done
    fi
}
