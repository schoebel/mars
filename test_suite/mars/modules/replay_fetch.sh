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

## this module provides functions to test independency of fetch and replay

#####################################################################
function replay_fetch_run
{
    local primary_host=${global_host_list[0]}
    local secondary_host=${global_host_list[1]}
    local res=${resource_name_list[0]}
    local writer_pid writer_script write_count
    local logfile length_logfile time_waited net_throughput

    lib_wait_for_initial_end_of_sync $primary_host $secondary_host $res \
                                  $resource_maxtime_initial_sync \
                                  $resource_time_constant_initial_sync \
                                  "time_waited"
    lib_vmsg "  ${FUNCNAME[0]}: sync time: $time_waited"

    lib_rw_start_writing_data_device $primary_host "writer_pid" \
                                     "writer_script"  0 2 $res ""

    marsadm_pause_cmd "replay" $secondary_host $res

    lib_wait_until_action_stops "replay" $secondary_host $res \
                                  $replay_fetch_maxtime_replay \
                                  $replay_fetch_time_constant_replay \
                                  "time_waited" 0 "net_throughput"
    lib_vmsg "  ${FUNCNAME[0]}: replay time: $time_waited"

    marsview_wait_for_state $secondary_host $res "disk" \
                            "Outdated\[.*${marsview_replay_flag}.*\]" \
                            $marsview_wait_for_state_time
    marsview_wait_for_state $secondary_host $res "repl" '-SF--' \
                            $marsview_wait_for_state_time || lib_exit 1

    marsadm_pause_cmd "fetch" $secondary_host $res

    lib_wait_until_fetch_stops "replay_fetch" $secondary_host $primary_host \
                               $res "logfile" "length_logfile" "time_waited" 0 \
                               "net_throughput"
    lib_vmsg "  ${FUNCNAME[0]}: fetch time: $time_waited"


    lib_rw_stop_writing_data_device $primary_host $writer_script "write_count" \
                                    $res
    main_error_recovery_functions["lib_rw_stop_scripts"]=

    case $replay_fetch_running_action in #(((
        replay)
            marsadm_do_cmd $secondary_host "resume-replay" $res || lib_exit 1

            lib_wait_until_action_stops "replay" $secondary_host $res \
                          $replay_fetch_maxtime_replay_after_disconnect \
                          $replay_fetch_time_constant_replay_after_disconnect \
                          "time_waited" 0 "net_throughput"
            lib_vmsg "  ${FUNCNAME[0]}: replay time: $time_waited"

            marsadm_check_warnings_and_disk_state $secondary_host $res \
                                               "replay_stopped_after_disconnect"
            marsview_wait_for_state $secondary_host $res "repl" \
                                    "-S-${marsview_replay_flag}-" \
                                    $marsview_wait_for_state_time || lib_exit 1
            marsadm_do_cmd $secondary_host "connect" $res || lib_exit 1
            ;;
        fetch)
            marsadm_do_cmd $secondary_host "connect" $res || lib_exit 1

            lib_wait_until_fetch_stops "replay_fetch" $secondary_host \
                                       $primary_host $res "logfile" \
                                       "length_logfile" "time_waited" 0 \
                                       "net_throughput"
            lib_vmsg "  ${FUNCNAME[0]}: fetch time: $time_waited"

            file_handling_check_equality_of_file_lengths $logfile \
                                                         $primary_host \
                                                         $secondary_host \
                                                         $length_logfile

            marsview_wait_for_state $secondary_host $res "disk" \
                                    "Outdated\[.*${marsview_replay_flag}.*\]" \
                                    $marsview_wait_for_state_time
            marsview_wait_for_state $secondary_host $res "repl" "-SF--" \
                                    $marsview_wait_for_state_time || lib_exit 1
            marsadm_do_cmd $secondary_host "resume-replay" $res || lib_exit 1
            ;;
            *) lib_exit 1 "invalid action $replay_fetch_running_action"
            ;;
    esac
    marsview_wait_for_state $secondary_host $res "disk" "Uptodate" \
                            $replay_fetch_maxtime_state_constant || lib_exit 1
    marsview_wait_for_state $secondary_host $res "repl" \
                            "-SF${marsview_replay_flag}-" \
                            $replay_fetch_maxtime_state_constant || lib_exit 1
}

# - start mars_dev_writer                    replay must run
# - pause-replay on secondary                 to (nearly) end
# - pause-fetch on secondary                 of fetched
# - resume-replay on secondary                logfile
# 
# - start mars_dev_writer                    the whole
# - pause-replay on secondary                 logfile must be
# - pause-fetch on secondary                 fetched
# - stop mars_dev_writer
# - resume-fetch on secondary
# 
# }
