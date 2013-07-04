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

function resource_prepare
{
    cluster_mount_mars_dir_all
    resource_insert_mars_module_all
    resource_leave_all
    resource_insert_mars_module_all
}

function resource_recreate_all
{
    local host primary_host
    for host in "${main_host_list[@]}"; do
        local size res
        for size in "${resource_device_size_list[@]}"; do
            res=$(lv_config_get_lv_name $size)
            resource_leave $host $res
            if [ -z "$primary_host" ]; then
                resource_create $host $size
                primary_host=$host
            else
                resource_join $host $size $primary_host
            fi
        done
    done
}

function resource_leave_all
{
    local host
    for host in "${main_host_list[@]}"; do
        local size res
        for size in "${resource_device_size_list[@]}"; do
            res=$(lv_config_get_lv_name $size)
            resource_leave $host $res
        done
    done
    resource_cleanup_all
}

function resource_cleanup_all
{
    cluster_rmmod_mars_all

    local host
    for host in "${main_host_list[@]}"; do
        local size res
        for size in "${resource_device_size_list[@]}"; do
            res=$(lv_config_get_lv_name $size)
            resource_rm_resource_dir $host $res
            cluster_remove_debugfiles $host
        done
    done
}

function resource_rm_resource_dir
{
    local host=$1 res=$2
    local dir="$(lib_linktree_get_resource_dir $res)"
    lib_vmsg "  removing directory $dir on $host"
    lib_remote_idfile $host "if [ -d $dir ]; then rm -rf $dir; fi" || lib_exit 1
}

function resource_leave
{
    local host=$1 res=$2
    if resource_is_data_device_mounted $host $res; then
        local dev=$(resource_get_name_data_device $res)
        mount_umount $host $dev $mount_test_mount_point || lib_exit 1
    fi

    if resource_joined $host $res; then
        resource_secondary $host $res
        local cmd
        for cmd in "down" "detach" "disconnect" "--force leave-resource"; do
            marsadm_do_cmd $host "$cmd" $res || lib_exit 1
        done
        marsadm_do_cmd $host  "wait-resource" "$res has-device-off"
        resource_check_links_after_leave $host $res
    fi
    resource_rm_resource_dir $host $res
}

function resource_secondary
{
    local host=$1 res="$2"
    marsadm_do_cmd $host "secondary" $res || lib_exit 1
    marsadm_do_cmd $host "wait-resource" "$res is-primary-off"
    resource_check_links_after_secondary $host $res
}

function resource_check_links_after_secondary
{
    local host=$1 res=$2 reslink_name link_value_expected link_status

    local link_name="$(lib_linktree_get_primary_linkname $res)"
    local link_value_expected="(none)"
    lib_linktree_check_link $host "$link_name" \
                                "$link_value_expected"
    link_status=$?
    if [ $link_status -ne ${main_link_status["link_ok"]} ]; then
        lib_exit 1 "resource $res on $host is not secondary"
    fi
}

function resource_check_links_after_leave
{
    local host=$1 res=$2
    local link_name="$(lib_linktree_get_primary_linkname $res)"
    local link_value_expected_list="."
    lib_linktree_check_link $host "$link_name" "$link_value_expected"
    link_status=$?
    if [ $link_status -eq ${main_link_status["link_ok"]} ]; then
        lib_exit 1 "resource $res on $host still exists"
        return 0
    fi
}

function resource_joined
{
    local host=$1 res="$2"
    local link_name="$(lib_linktree_get_resource_dir $res)/data-$host"
    local link_value_expected=(".")
    lib_linktree_check_link $host "$link_name" "$link_value_expected"
    link_status=$?
    if [ $link_status -eq ${main_link_status["link_ok"]} ]; then
        lib_vmsg "  resource $res on $host exists"
        return 0
    else
        lib_vmsg "  resource $res on $host does not exist"
        return 1
    fi
}


function resource_run
{
    resource_create ${main_host_list[0]} ${resource_device_size_list[0]}
    resource_join ${main_host_list[1]} ${resource_device_size_list[0]} \
                  ${main_host_list[0]}
}

function resource_up
{
    local host=$1 res=$2 rc
    marsadm_do_cmd $host "up" $res
    rc=$?
    return $rc
}

function resource_create
{
    local host=$1 res_size=$2
    local res=$(lv_config_get_lv_name $res_size)

    local dev="$(lv_config_get_lv_device $res_size)"
    lib_remote_check_device_fs_idfile $host $dev
    if ! resource_up $host $res; then
        if [ "$resource_create_flag" = "--force" ]; then
            resource_rm_resource_dir $host $res
        fi
        marsadm_do_cmd $host "create-resource $resource_create_flag" \
                             "$res $dev" || lib_exit 1
        marsadm_do_cmd $host "wait-resource" "$res has-device" || lib_exit 1
        local role
        role=($marsadm_get_role $host $res) || lib_exit 1
        if [ "$role" = "secondary" ]; then
            marsadm_do_cmd $host "primary" $res
        fi
    fi
    resource_check_links_after_create $host $res
    resource_check_data_device_after_create $host $res
    resource_check_underlying_device $host $dev
}

function resource_get_name_data_device
{
    local res=$1
    echo /dev/mars/$res 
}

function resource_is_data_device_mounted
{
    local host=$1 res=$2 rc
    local dev=$(resource_get_name_data_device $res)
    mount_is_device_mounted $host $dev
}

function resource_check_data_device_after_create
{
    local host=$1 res=$2
    local dev=$(resource_get_name_data_device $res)
    lib_vmsg "  checking existence of device $dev on $host"
    lib_remote_idfile $host "ls -l $dev" || lib_exit 1
    resource_check_mount_point_directory $host
    if ! mount_is_device_mounted $host $dev $mount_test_mount_point
    then
        mount_mount $host $dev $mount_test_mount_point
    fi
    resource_check_whether_rmmod_mars_fails $host $dev
    mount_umount $host $dev $mount_test_mount_point || lib_exit 1
}

function resource_check_whether_rmmod_mars_fails
{
    local host=$1 dev=$2 rc
    lib_vmsg "  checking whether rmmod mars fails on $host"
    lib_remote_idfile $host "rmmod mars"
    rc=$?
    if [ $rc -eq 0 ]; then
        local dev=
        lib_exit 1 "rmmod mars could be removed while $dev is mounted"
    fi
}

function resource_check_mount_point_directory
{
    local host=$1
    lib_vmsg "  checking mount point $mount_test_mount_point on $host"
    lib_remote_idfile $host "if [ ! -d $mount_test_mount_point ]; then mkdir $mount_test_mount_point; fi" \
                                                                                                            || lib_exit 1
}

function resource_check_underlying_device
{
    local host=$1 dev=$2 rc
    resource_check_mount_point_directory $host
    lib_vmsg "  checking whether mounting $dev on $mount_test_mount_point on $host fails"
    mount_mount $host $dev $mount_test_mount_point 
    rc=$?
    if [ $rc -eq 0 ]; then
        lib_exit 1
    fi
}

function resource_join
{
    local host=$1 res_size=$2 primary_host=$3
    local res=$(lv_config_get_lv_name $res_size)

    local dev="$(lv_config_get_lv_device $res_size)"
    lib_remote_check_device_fs_idfile $host $dev
    if ! resource_up $host $res; then
        marsadm_do_cmd $host "join-resource" "$res $dev" || lib_exit 1
    fi
    resource_check_links_after_join $host $res $primary_host
    resource_check_underlying_device $host $dev
}

function resource_insert_mars_module_all
{
    local host
    for host in "${main_host_list[@]}"; do
        resource_insert_mars_module $host
    done
}

function resource_insert_mars_module
{
    local host=$1
    cluster_create_debugfiles $host
    lib_vmsg "  inserting mars module on $host"
    lib_remote_idfile $host 'grep -w "^mars" /proc/modules || modprobe mars' || lib_exit 1
}

function resource_check_links_after_join
{
    local host=$1 res=$2 primary_host=$3 

    local reslink_name link_value_expected link_status

    local link_name="$(lib_linktree_get_primary_linkname $res)"
    local link_value_expected="$primary_host"
    lib_linktree_check_link $host "$link_name" "$link_value_expected"
    link_status=$?
    if [ $link_status -ne ${main_link_status["link_ok"]} ]; then
        lib_exit 1 "resource $res on $host has not been joined"
    fi
}

function resource_check_links_after_create
{
    local host=$1 res=$2 reslink_name link_value_expected link_status

    local link_name="$(lib_linktree_get_primary_linkname $res)"
    local link_value_expected="$host"
    lib_linktree_check_link $host "$link_name" "$link_value_expected"
    link_status=$?
    if [ $link_status -ne ${main_link_status["link_ok"]} ]; then
        lib_exit 1 "resource $res on $host has not been created"
    fi
}

