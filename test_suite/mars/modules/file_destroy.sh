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

function file_destroy_run
{

    local primary_host="${global_host_list[0]}"
    local secondary_host="${global_host_list[1]}"
    local res=${resource_name_list[0]}
    local logfile length_logfile writer_pid writer_script write_count 
    local time_waited net_throughput

    lib_wait_for_initial_end_of_sync $primary_host $secondary_host $res \
                                     $resource_maxtime_initial_sync \
                                     $resource_time_constant_initial_sync \
                                     "time_waited"
    lib_vmsg "  ${FUNCNAME[0]}: sync time: $time_waited"


    mount_mount_data_device $primary_host $res
    resource_clear_data_device $primary_host $res


    lib_rw_start_writing_data_device $primary_host "writer_pid" \
                                     "writer_script" 0 2 $res ""

    file_destroy_down_secondary $secondary_host $res
    marsadm_do_cmd $secondary_host "connect" $res || lib_exit 1

    file_destroy_sleep $file_destroy_duration_of_writer_after_secondary_down

    lib_rw_stop_writing_data_device $primary_host $writer_script "write_count"
    main_error_recovery_functions["lib_rw_stop_scripts"]=

    lib_wait_until_fetch_stops "file_destroy" $secondary_host $primary_host \
                               $res "logfile" "length_logfile" "time_waited" 0 \
                               "net_throughput"
    lib_vmsg "  ${FUNCNAME[0]}: fetch time: $time_waited"


    file_handling_check_equality_of_file_lengths $logfile $primary_host \
                                                $secondary_host $length_logfile

    file_destroy_dd_on_logfile $secondary_host $logfile $length_logfile

    file_destroy_up_secondary $secondary_host $res

    lib_wait_until_action_stops "replay" $secondary_host $res \
                                  $file_destroy_maxtime_apply \
                                  $file_destroy_time_constant_apply \
                                  "time_waited" 0 "net_throughput"
    lib_vmsg "  ${FUNCNAME[0]}: apply time: $time_waited"

    marsview_wait_for_state $secondary_host $res "disk" "Outdated\[.*A.*\]" \
                            $marsview_wait_for_state_time || lib_exit 1
    marsview_wait_for_state $secondary_host $res "repl" "-SFA-" \
                            $marsview_wait_for_state_time || lib_exit 1

    file_destroy_repair_logfile $secondary_host $logfile
    marsview_wait_for_state $secondary_host $res "disk" "Uptodate" \
                            $marsview_wait_for_state_time
    marsview_wait_for_state $secondary_host $res "repl" "-SFA-" \
                            $marsview_wait_for_state_time
}

function file_destroy_repair_logfile
{
    local secondary_host=$1 logfile=$2
    
    marsadm_do_cmd $secondary_host "down" $res || lib_exit 1
    lib_remote_idfile $secondary_host \
                      "truncate -s -$file_destroy_patch_length $logfile" || \
                                                                    lib_exit 1
    marsadm_do_cmd $secondary_host "connect" $res || lib_exit 1
    marsadm_do_cmd $secondary_host "up" $res || lib_exit 1
}

function file_destroy_up_secondary
{
    local secondary_host=$1 res=$2
    marsadm_do_cmd $secondary_host "up" $res || lib_exit 1
    # in case of an error get as much info as possible
    local maxcount=10 count
    for count in $(seq 1 1 $maxcount); do
        if ! marsview_check $secondary_host $res "disk" "Outdated\[.*A.*\]"; then
            lib_linktree_print_linktree $secondary_host
            continue;
        fi
        if ! marsview_check $secondary_host $res "repl" "-SFA-"; then
            lib_linktree_print_linktree $secondary_host
            continue;
        fi
        break
    done
}


function file_destroy_down_secondary
{
    local secondary_host=$1 res=$2

    marsadm_do_cmd $secondary_host "down" $res || lib_exit 1
    marsview_wait_for_state $secondary_host $res "disk" "Detached" \
                            $marsview_wait_for_state_time || lib_exit 1
}

function file_destroy_sleep
{
    local sleep_time=$1
    lib_vmsg "  sleeping for $sleep_time seconds"
    sleep $file_destroy_duration_of_writer_after_secondary_down
}

function file_destroy_dd_on_logfile
{
    [ $# -eq 3 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local host=$1 logfile=$2 length=$3
    local patch_length=$file_destroy_patch_length
    local offset=$(($length - $patch_length))
    lib_vmsg " patching the last $patch_length bytes in $host:$logfile"
    lib_remote_idfile $host "printf '%.${patch_length}d' | dd of=$logfile bs=1 conv=notrunc count=$patch_length seek=$offset" || lib_exit 1
}
