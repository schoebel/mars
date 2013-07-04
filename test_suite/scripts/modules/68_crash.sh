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

## this module provides functions to test system crashes in a running
## mars installation

function crash_run
{
    local primary_host=${main_host_list[0]}
    local secondary_host=${main_host_list[1]}
    local lilo_label_name="${main_host_bootloader_label_list[0]}"
    local dev=$(lv_config_get_lv_device ${resource_device_size_list[0]})
    local res=$(lv_config_get_lv_name ${resource_device_size_list[0]})
    local writer_pid writer_script logfile length_logfile
    local waited=0 error_ocurred=0

    mount_mount_data_device

    lib_rw_start_writing_data_device "writer_pid" "writer_script"

    lib_vmsg "  sleep $crash_time_from_write_start_to_reboot seconds"
    sleep $crash_time_from_write_start_to_reboot

    marsadm_set_proc_sys_mars_parameter $primary_host \
                                        "logger_completion_semantics" \
                                        $crash_logger_completion_semantics
    marsadm_set_proc_sys_mars_parameter $primary_host \
                                        "aio_sync_mode" \
                                        $crash_aio_sync_mode
    crash_reboot $primary_host $secondary_host $crash_maxtime_reboot \
                 $crash_maxtime_to_become_unreachable \
                 $lilo_label_name $res

    cluster_mount_mars_dir_all

    lib_linktree_print_linktree $primary_host

    resource_insert_mars_module $primary_host

    marsview_wait_for_state $primary_host $res "disk" "Uptodate" \
                            $crash_maxtime_state_constant
    marsview_wait_for_state $primary_host $res "repl" "-SFA-" \
                            $crash_maxtime_state_constant
    lib_wait_until_action_stops "syncstatus" $secondary_host $res \
                                  $crash_maxtime_sync \
                                  $crash_time_constant_sync

    lib_wait_until_fetch_stops "crash" $secondary_host $primary_host $res \
                               "logfile" "length_logfile"

    marsview_check $secondary_host $res "disk" "Uptodate*" || \
                                                        let error_occured+=1
    marsview_check $secondary_host $res "repl" "-SFA-" || let error_occured+=1

    lib_rw_compare_checksums $primary_host $secondary_host $dev

    if [ $error_ocurred -gt 0 ]; then
        echo "error_ocurred = $error_ocurred" >&2
        for host in $primary_host $secondary_host; do
            lib_linktree_print_linktree $host
        done
        lib_exit 1
    fi

    crash_write_data_device_and_calculate_checksums $primary_host \
                                                    $secondary_host $res $dev

}

function crash_write_data_device_and_calculate_checksums
{
    local primary_host=$1 secondary_host=$2 res=$3 dev=$4
    local writer_pid writer_script waited
    mount_mount_data_device
    lib_rw_start_writing_data_device "writer_pid" "writer_script"
    lib_rw_stop_writing_data_device $writer_script 
    lib_wait_until_action_stops "replay" $secondary_host $res \
                                  $resize_maxtime_sync \
                                  $resize_time_constant_sync

    marsview_wait_for_state $secondary_host $res "disk" "Uptodate" \
                            $crash_maxtime_state_constant
    marsview_wait_for_state $secondary_host $res "repl" "-SFA-" \
                            $crash_maxtime_state_constant
    lib_rw_compare_checksums $primary_host $secondary_host $dev
}

function crash_reboot
{
    [ $# -eq 6 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local primary_host=$1 secondary_host=$2 maxtime_to_reboot=$3 \
    local maxtime_to_become_unreachable=$4
    local lilo_label_name=$5 res=$6
    local pids_to_kill host
    local reboot_cmd="reboot -n -f"

    install_mars_activate_kernel_to_boot_with_lilo $primary_host \
                                                   $lilo_label_name

    main_error_recovery_functions["lib_rw_stop_script"]=
    
    for host in $primary_host $secondary_host; do
        lib_linktree_print_linktree $host
    done

    lib_vmsg "  reboot of $primary_host"
    lib_remote_idfile $primary_host "$reboot_cmd" &
    # pstree -lp writes s.th. like
    # init(1)---xterm(345)
    pids_to_kill=$(pstree -lp $! | sed 's/[^(][^(]*(\([0-9][0-9]*\))/\1 /g')

    lib_linktree_print_linktree $secondary_host

    crash_wait_to_become_unreachable $primary_host "$pids_to_kill"

    lib_linktree_print_linktree $secondary_host

#     marsadm_do_cmd $secondary_host "disconnect" $res || lib_exit 1
# 
#     sleep 180
# 
#     lib_linktree_print_linktree $secondary_host
#     
#     marsadm_do_cmd $secondary_host "connect" $res || lib_exit 1
# 
    crash_wait_to_become_reachable $primary_host

    for host in $primary_host $secondary_host; do
        lib_linktree_print_linktree $host
    done
}

function crash_wait_to_become_reachable
{
    local host=$1
    local ssh_pid waited=0
    while [ $waited -lt $maxtime_to_reboot ]; do
        if [ -z "$ssh_pid" ]; then
            if ping -c1 -W10 $host; then
                lib_vmsg "  trying a ssh command on $host"
                lib_remote_idfile $host date &
                ssh_pid=$!
            else
                lib_vmsg "  waited $waited for $host to become reachable (ping does not succeed)"
                sleep $crash_sleep_between_control_cmds
            fi
        else
            if ps -fp $ssh_pid; then
                lib_vmsg "  waited $waited for $host to become reachable (ssh active(pid=$ssh_pid)"
                sleep $crash_sleep_between_control_cmds
            else
                break
            fi
        fi
        let waited+=$crash_sleep_between_control_cmds
    done
    if [ $waited -ge $maxtime_to_reboot ]; then
        lib_exit 1 "  duration $maxtime_to_reboot to become reachable exceeded"
    fi
}

function crash_wait_to_become_unreachable
{
    local host=$1 pids_to_kill="$2" pid
    local waited=0
    while [ $waited -lt $maxtime_to_become_unreachable ]; do
        if ping -c1 -W10 $host; then
            lib_vmsg "  waited $waited for $host to become unreachable (ping succeeds)"
            sleep $crash_sleep_between_control_cmds
        else
            break
        fi
        let waited+=$crash_sleep_between_control_cmds
    done
    for pid in $pids_to_kill; do
        if ps -fp $pid; then
            kill -1 $pid
            sleep 1
            if ps -fp $pid; then
                kill -9 $pid
            fi
        fi
    done
    if [ $waited -ge $maxtime_to_become_unreachable ]; then
        lib_exit 1 "  duration $maxtime_to_become_unreachable to become unreachable exceeded"
    fi
}
