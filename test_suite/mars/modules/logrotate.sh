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

function logrotate_run
{
    local primary_host="${global_host_list[0]}"
    local secondary_host="${global_host_list[1]}"
    local res=${resource_name_list[0]}
    local dev=$(lv_config_get_lv_device $res)
    local writer_pid writer_script write_count

    mount_mount_data_device $primary_host $res
    resource_clear_data_device $primary_host $res


    lib_rw_start_writing_data_device $primary_host "writer_pid" \
                                     "writer_script" 0 0 $res ""

    logrotate_loop $primary_host $res $logrotate_number_of_rotate_loops \
                   $logrotate_sleep_time_between_rotates

    lib_rw_stop_writing_data_device $primary_host $writer_script "write_count"
    main_error_recovery_functions["lib_rw_stop_scripts"]=

    logrotate_wait_for_umount_data_device $primary_host $dev \
                                          ${resource_mount_point_list[$res]} \
                                          $logrotate_maxtime_state_constant


    marsview_wait_for_state $secondary_host $res "disk" "Uptodate" \
                            $logrotate_maxtime_state_constant || lib_exit 1
    marsview_wait_for_state $secondary_host $res "repl" "-SFA-" \
                            $logrotate_maxtime_state_constant || lib_exit 1

    lib_rw_compare_checksums $primary_host $secondary_host $res 0 "" ""
}

function logrotate_wait_for_umount_data_device
{
    local host=$1 dev=$2 mount_point=$3 maxwait=$4
    local waited=0 rc
    while true; do
        mount_umount $primary_host $dev ${resource_mount_point_list[$res]}
        rc=$?
        if [ $rc -eq 0 ]; then
            break
        fi
        sleep 1
        let waited+=1
        lib_vmsg "  waited $waited for unmount $mount_point ($dev) on $host"
        if [ $(($waited % 5)) -eq 0 ]; then
            lib_vmsg "  printing link tree on $host"
            lib_linktree_print_linktree $host
        fi
        if [ $waited -ge $maxwait ]; then
            lib_exit 1 "maxtime $maxwait exceeded"
        fi
    done
}

function logrotate_loop
{
    local host=$1 res=$2 number_of_rotate_loops=$3 sleep_time_between_rotates=$4
    local logrotate_rc_req=0 logrotate_msg="succeed"
    local count=0 logfile
    local logrotate_rc_act rc_prim rc_desig_prim
    marsadm_host_is_primary $host $res; rc_prim=$?
    marsadm_host_is_designated_primary $host $res; rc_desig_prim=$?
    if [ $rc_prim -ne 1 -o $rc_desig_prim -ne 1 ]; then
        logrotate_rc_req=1
        logrotate_msg="fail"
    fi
    lib_vmsg "starting rotate loop on $host (primary=$rc_prim, desig.prim=$rc_desig_prim, logrotate must $logrotate_msg)"
    while [ $count -lt $number_of_rotate_loops ]; do
        marsadm_do_cmd $host "log-rotate" $res
        logrotate_rc_act=$?
        if [ \( $logrotate_rc_act -ne 0 -a $logrotate_rc_req -eq 0 \) \
             -o \( $logrotate_rc_act -eq 0 -a $logrotate_rc_req -ne 0 \) ]
        then
            lib_exit 1 "required rc = $logrotate_rc_req != $logrotate_rc_act = act. rc"
        fi
        logfile=$(marsadm_get_last_logfile $host $res $host) || lib_exit 1
        lib_vmsg "  last logfile $host:$logfile"
        if [ $(($count % $logrotate_number_of_rotates_before_delete)) -eq 0 ]
        then
            marsadm_do_cmd $host "log-delete-all" $res || lib_exit 1
        fi
        sleep $sleep_time_between_rotates
        let count+=1
    done
}

# starts an endless loop which calls marsadm log-rotate or log-delete for a 
# given resource on a remote host
# the pid of the started process will be returned in the variable named by $4
# the name of the started script will be returned in the variable named by $5
function logrotate_start_action_loop
{
    [ $# -eq 6 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local host=$1 action=$2 res=$3 sleep_time=$4 varname_pid=$5
    local varname_script=$6
    local dirname dir
    local script=${logrotate_action_script_prefix}${action}.$$
    # this script will be started
    echo '#/bin/bash
while true; do
    marsadm log-'"$action"' '"$res"'
    sleep '"$sleep_time"'
done' >$script
    lib_start_script_remote_bg $host $script $varname_pid \
                                         $varname_script "rm"
    main_error_recovery_functions["lib_rw_stop_scripts"]+="$host $script "
}


