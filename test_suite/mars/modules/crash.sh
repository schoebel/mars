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
    local primary_host=${global_host_list[0]}
    local secondary_host=${global_host_list[1]}
    local mars_dev=$(lv_config_get_lv_device ${cluster_mars_dir_lv_name_list[$primary_host]})
    local boot_label_name="${global_host_bootloader_label_list[$primary_host]}"
    local res=${resource_name_list[0]}
    local dev=$(lv_config_get_lv_device $res)
    local writer_pid writer_script logfile length_logfile time_waited
    local net_throughput
    local waited=0 error_ocurred=0

    mount_mount_data_device $primary_host $res
    resource_clear_data_device $primary_host $res

    lib_rw_start_writing_data_device $primary_host "writer_pid" \
                                     "writer_script" 0 0 $res ""

    lib_vmsg "  sleep $crash_time_from_write_start_to_reboot seconds"
    sleep $crash_time_from_write_start_to_reboot

    marsadm_set_proc_sys_mars_parameter $primary_host \
                                        "logger_completion_semantics" \
                                        $crash_logger_completion_semantics
    marsadm_set_proc_sys_mars_parameter $primary_host \
                                        "aio_sync_mode" \
                                        $crash_aio_sync_mode
    crash_reboot $primary_host $secondary_host $mars_dev $crash_maxtime_reboot \
                 $crash_maxtime_to_become_unreachable \
                 "$boot_label_name"

    lib_linktree_print_linktree $primary_host

    cluster_insert_mars_module $primary_host

    marsview_wait_for_state $primary_host $res "disk" "Uptodate" \
                                                $crash_maxtime_state_constant
    lib_linktree_print_linktree $primary_host

    marsview_wait_for_state $primary_host $res "repl" "-SFA-" \
                                                $crash_maxtime_state_constant
    lib_wait_until_action_stops "syncstatus" $secondary_host $res \
                                  $crash_maxtime_sync \
                                  $crash_time_constant_sync "time_waited" 0 \
                                  "net_throughput"
    lib_vmsg "  ${FUNCNAME[0]}: sync time: $time_waited"


    lib_wait_until_fetch_stops "crash" $secondary_host $primary_host $res \
                               "logfile" "length_logfile" "time_waited" 0 \
                               "net_throughput"
    lib_vmsg "  ${FUNCNAME[0]}: fetch time: $time_waited"


    marsview_wait_for_state $secondary_host $res "disk" "Uptodate*" \
                        $marsview_wait_for_state_time || let error_occured+=1
    marsview_wait_for_state $secondary_host $res "repl" "-SFA-" \
                        $marsview_wait_for_state_time || let error_occured+=1

    lib_rw_compare_checksums $primary_host $secondary_host $res 0 "" ""

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
    local writer_pid writer_script write_count time_waited net_throughput
    mount_mount_data_device $primary_host $res
    resource_clear_data_device $primary_host $res
    lib_rw_start_writing_data_device $primary_host "writer_pid" \
                                     "writer_script" 0 0 $res ""
    lib_rw_stop_writing_data_device $primary_host $writer_script "write_count"
    main_error_recovery_functions["lib_rw_stop_scripts"]=
    lib_wait_until_action_stops "replay" $secondary_host $res \
                                  $crash_maxtime_apply \
                                  $crash_time_constant_apply "time_waited" 0 \
                                  "net_throughput"
    lib_vmsg "  ${FUNCNAME[0]}: apply time: $time_waited"


    marsview_wait_for_state $secondary_host $res "disk" "Uptodate" \
                                                $crash_maxtime_state_constant
    marsview_wait_for_state $secondary_host $res "repl" "-SFA-" \
                                                $crash_maxtime_state_constant
    mount_umount_data_device $primary_host $res
    lib_rw_compare_checksums $primary_host $secondary_host $res 0 "" ""
}

function xx
{
    crash_reboot istore-test-bs7 istore-test-bap7 $(lv_config_get_lv_device ${cluster_mars_dir_lv_name_list[$primary_host]}) $crash_maxtime_reboot $crash_maxtime_to_become_unreachable ""
}

function crash_reboot
{
    [ $# -eq 6 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local primary_host=$1 secondary_host=$2 mars_dev=$3 maxtime_to_reboot=$4
    local maxtime_to_become_unreachable=$5
    local boot_label_name="$6"
    local pids_to_kill host
    if [ -z "$crash_print_linktree_during_reboot" ]; then
        lib_exit 1 "variable crash_print_linktree_during_reboot not set"
    fi
    if [ $crash_print_linktree_during_reboot -eq 1 -a -z "$secondary_host" ]
    then
        lib_exit 1 "to print symlink trees secondary_host must be given"
    fi
    if [ "${global_host_bootloader_list[$primary_host]}" = "lilo" ]; then
	install_mars_activate_kernel_to_boot_with_lilo $primary_host \
						       "$boot_label_name"
    fi

    main_error_recovery_functions["lib_rw_stop_scripts"]=
    
    if [ $crash_print_linktree_during_reboot -eq 1 ]; then
        for host in $primary_host $secondary_host; do
            lib_linktree_print_linktree $host
        done
    fi

    crash_reboot_host $primary_host

    # the reboot cmd must be given in the background and the corresponding
    # ssh process manually killed.
    # pstree -lp writes s.th. like
    # init(1)---xterm(345)
    pids_to_kill=$(pstree -lp $! | sed 's/[^(][^(]*(\([0-9][0-9]*\))/\1 /g')

    if [ $crash_print_linktree_during_reboot -eq 1 ]; then
        lib_linktree_print_linktree $secondary_host
    fi

    crash_wait_to_become_unreachable $primary_host "$pids_to_kill" \
                                     $maxtime_to_become_unreachable

    if [ $crash_print_linktree_during_reboot -eq 1 ]; then
        lib_linktree_print_linktree $secondary_host
    fi

    crash_wait_to_become_reachable $primary_host $maxtime_to_reboot

    cluster_mount_mars_dir $primary_host $mars_dev

    if [ $crash_print_linktree_during_reboot -eq 1 ]; then
        for host in $primary_host $secondary_host; do
            lib_linktree_print_linktree $host
        done
    fi
}

function crash_reboot_host
{
    local host=$1
    local reboot_cmd="reboot -n -f"
    lib_vmsg "  reboot of $host"
    lib_remote_idfile $host "$reboot_cmd" &
}

function crash_wait_to_become_reachable
{
    local host=$1 maxtime_to_reboot=$2
    local waited=0
    while true; do
        if ping -c1 -W10 $host; then
            lib_vmsg "  trying a ssh command on $host"
            if lib_remote_idfile $host date; then
                break
            else
                lib_vmsg "  waited (total wait time (ping and ssh) = $waited) for $host to accept a ssh connection"
            fi
        else
            lib_vmsg "  waited $waited for $host to become reachable (ping does not succeed)"
        fi
        let waited+=$crash_sleep_between_control_cmds
        if [ $waited -ge $maxtime_to_reboot ]; then
            lib_exit 1 "  maxtime $maxtime_to_reboot exceeded"
        fi
    done
}

function crash_wait_to_become_unreachable
{
    [ $# -eq 3 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local host=$1 pids_to_kill="$2" maxtime_to_become_unreachable=$3
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
    lib_vmsg "  killing background processes $pids_to_kill on local host"
    for pid in $pids_to_kill; do
        if ps -fp $pid; then
            lib_vmsg "  kill -1 $pid on local host"
            kill -1 $pid
            sleep 1
            lib_vmsg "  checking whether $pid has been killed"
            if ps -fp $pid; then
                kill -9 $pid
                lib_vmsg "  kill -9 $pid on local host"
            fi
        fi
    done
    if [ $waited -ge $maxtime_to_become_unreachable ]; then
        lib_exit 1 "  maxwait $maxtime_to_become_unreachable to become unreachable exceeded"
    fi
}
