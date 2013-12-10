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

function resize_prepare
{
    local primary_host=${main_host_list[0]}
    local secondary_host="${main_host_list[1]}"
    local res=${resource_name_list[0]}
    local data_lv_size_orig=$(lv_config_get_lv_size_from_name $res)
    local dev=$(lv_config_get_lv_device $res)
    local host time_waited

    resize_check_variables 

    resize_resize_to_orig_size $primary_host $secondary_host $dev \
                               $data_lv_size_orig
    resource_leave_all
    for host in $primary_host $secondary_host; do
        lv_config_resize_device $host $dev $data_lv_size_orig
    done
    resource_prepare
    resource_run_first 
    lib_wait_for_initial_end_of_sync $primary_host $secondary_host $res \
                                     $resource_maxtime_initial_sync \
                                     $resource_time_constant_initial_sync \
                                     "time_waited"
    lib_vmsg "  ${FUNCNAME[0]}: sync time: $time_waited"

    lib_rw_compare_checksums $primary_host $secondary_host $res 0 "" ""

}

function resize_check_variables 
{
    if [ -z "$resize_size_to_add" ]; then
        lib_exit 1 "resize_size_to_add not set"
    fi
    if [ -z "$resize_diff_to_phsyical" ]; then
        lib_exit 1 "resize_diff_to_phsyical not set"
    fi
    # Because we check the extension of the file system by writing an amount
    # of size_new - 1G we need gaps between old and new size which are big
    # enough:
    # size_old + 1G <= size_new_mars_data_device - 1G = \
    #       size_old + resize_size_to_add - resize_diff_to_phsyical - 1G
    if [ $resize_size_to_add -lt 3 ]; then
        lib_exit 1 "resize_size_to_add = $resize_size_to_add must be >= 3"
    fi
    if [ $(($resize_size_to_add - $resize_diff_to_phsyical)) -lt 2 ]; then
        lib_exit 1 "resize_size_to_add - resize_diff_to_phsyical = $(($resize_size_to_add - $resize_diff_to_phsyical)) must be >= 2"
    fi
}

function resize_run
{
    local primary_host=${main_host_list[0]}
    local secondary_host=${main_host_list[1]}
    local res=${resource_name_list[0]}
    local data_lv_size_orig=$(lv_config_get_lv_size_from_name $res)
    local data_lv_size_new=$(($data_lv_size_orig + $resize_size_to_add))
    local mars_data_dev_size_new=$((data_lv_size_new \
                                    - $resize_diff_to_phsyical))
    local dev=$(lv_config_get_lv_device $res)
    local writer_pid writer_script

    mount_mount_data_device
    resource_clear_data_device $primary_host $res

    lib_rw_start_writing_data_device $primary_host "writer_pid" \
                                     "writer_script" 0 1 $res

    resize_do_resize $primary_host $secondary_host $res $dev \
                     $data_lv_size_new $mars_data_dev_size_new


    resize_check_resize_post_conditions $primary_host $secondary_host \
                                        $res $dev $mars_data_dev_size_new \
                                        $writer_script
    resize_resize_to_orig_size $primary_host $secondary_host $dev \
                               $data_lv_size_orig
}

function resize_check_resize_post_conditions
{
    [ $# -eq 6 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local primary_host=$1 secondary_host=$2 res=$3 dev=$4
    local mars_data_dev_size_new=$5 writer_script=$6
    local write_count test_size
    
    lib_linktree_check_link_int_value $secondary_host $res "syncstatus" \
                                      $mars_data_dev_size_new 1000000000
    # after sync disk state must be Outdated || Uptodate
    marsview_wait_for_state $secondary_host $res "disk" ".*date.*" \
                            $marsview_wait_for_state_time || lib_exit 1

    if [ -n "$writer_script" ]; then
        lib_rw_stop_writing_data_device $primary_host $writer_script \
                                        "write_count"
        main_error_recovery_functions["lib_rw_stop_scripts"]=
    fi

    local should_fail=0 test_file
    if [ $resource_fs_on_data_device_necessary -eq 1 ]; then
        test_file=${resource_mount_point_list[$res]}/resize_test
    else
        test_file=$(resource_get_data_device $res)
    fi
    for test_size in $(($mars_data_dev_size_new - 1)) $mars_data_dev_size_new
    do
        datadev_full_dd_on_device $primary_host $test_file $test_size 4711 \
                                  $should_fail
        should_fail=1
        lib_remote_idfile $primary_host \
                          "if ls -l $test_file; then rm -f $test_file;fi" \
                                                                || lib_exit 1
    done

    mount_umount_data_device $primary_host $res
    lib_wait_for_secondary_to_become_uptodate_and_cmp_cksums "resize" \
                                  $secondary_host $primary_host $res \
                                  $dev $mars_data_dev_size_new
}

function resize_do_resize
{
    [ $# -eq 6 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local primary_host=$1 secondary_host=$2 res=$3 dev=$4 data_lv_size_new=$5
    local mars_data_dev_size_new=$6
    local mars_data_dev=$(resource_get_data_device $res)
    local host time_waited net_throughput

    for host in $primary_host $secondary_host; do
        lv_config_resize_device $host $dev $data_lv_size_new
        lib_linktree_check_link_int_value $host $res "actsize" \
                                          $data_lv_size_new 1000000000
    done

    for role in "primary" "secondary"; do
        eval host='$'${role}_host
        marsadm_do_cmd $host "pause-sync" $res || lib_exit 1
        marsview_wait_for_state $host $res "disk" ".*date.*" \
                                $marsview_wait_for_state_time || lib_exit 1
        marsview_wait_for_state $host $res "repl" "--FA-" \
                                $marsview_wait_for_state_time || lib_exit 1
    done

    marsadm_do_cmd $primary_host "resize" "$res ${mars_data_dev_size_new}G" || \
                                                                lib_exit 1
    for host in $primary_host $secondary_host; do
        marsadm_do_cmd $host "resume-sync" $res || lib_exit 1
    done

    if [ $resource_fs_on_data_device_necessary -eq 1 ]; then
        resize_extend_fs $primary_host $mars_data_dev $res
    fi

    lib_wait_until_action_stops "syncstatus" $secondary_host $res \
                                  $resize_maxtime_sync \
                                  $resize_time_constant_sync "time_waited" 0 \
                                  "net_throughput"
    lib_vmsg "  ${FUNCNAME[0]}: sync time: $time_waited"
}

function resize_extend_fs
{
    local host=$1 dev=$2 res=$3
    local fs_type=${resource_fs_type_list[$res]}
    if [ -z "$fs_type" ]; then
        lib_exit 1 "resource $res missing in resource_fs_type_list"
    fi
    lib_vmsg "  extending $host:$dev (type $fs_type)"
    lib_remote_idfile $primary_host \
                      ${lv_config_fs_type_grow_cmd_list[$fs_type]} $dev \
                                                                || lib_exit 1
}

function resize_resize_to_orig_size
{
    local primary_host=$1 secondary_host=$2 dev=$3 data_lv_size_orig=$4
    local host

    resource_leave_all
    for host in $primary_host $secondary_host; do
        lv_config_resize_device $host $dev $data_lv_size_orig
        lib_rw_remote_check_device_fs $host $dev ${resource_fs_type_list[$res]}
    done
}

# TODO for i in $(seq 1 1 5);do  f=/mnt/test/f$i; date +'%Y%m%d%H%M%S'; dd if=/dev/vg-mars/lv-20 conv=fsync of=$f bs=4K count=125K ; rm -f $f; date +'%Y%m%d%H%M%S';  done 

