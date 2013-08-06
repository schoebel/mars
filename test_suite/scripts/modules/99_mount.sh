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
    lib_vmsg "  mounting dev $dev on $mount_point on $host"
    lib_remote_idfile $host mount -t $fs_type $dev $mount_point
    return $?
}

function mount_is_device_mounted
{
    local host=$1 dev=$2 rc
    lib_vmsg "  checking whether $dev is mounted on $host"
    lib_remote_idfile $host "mount | grep '^$dev on'"
    rc=$?
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
    local res_no=${1:-0}
    local res=${resource_name_list[$res_no]}
    local host=${main_host_list[0]} 
    local dev=$(resource_get_name_data_device $res)
    local mount_point=${resource_mount_point_list[$res]}
    lib_rw_mount_data_device $host $dev $mount_point
}

function mount_umount_data_device
{
    local res_no=${1:-0}
    local res=${resource_name_list[$res_no]}
    local host=${main_host_list[0]} 
    local dev=$(resource_get_name_data_device $res)
    local mount_point=${resource_mount_point_list[$res]}
    if mount_is_dir_mountpoint $host $mount_point; then
        mount_umount $host $dev $mount_point
    fi
}

