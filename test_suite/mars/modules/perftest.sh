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

function perftest_check_variables
{
        [ -z "$perftest_action" ] && lib_exit 1 "no action defined"
        case $perftest_action in # ((
            replay|fetch|write|sync|fetch_and_replay)  :
                ;;
               *) lib_exit 1 "invalid action $perftest_action"
                ;;
        esac
}

function perftest_run
{
    local primary_host=${global_host_list[0]}
    local secondary_host=${global_host_list[1]}
    local res=${resource_name_list[0]}

    perftest_check_variables

    cluster_remove_debugfiles $primary_host
    cluster_create_debugfiles $primary_host

    perftest_prepare_${perftest_action} $primary_host $secondary_host $res \
                                        $perftest_parallel_writer \
                                        $perftest_result_type \
                                        ${#resource_name_list[*]}

    case $perftest_action in # ((((
        fetch|sync|fetch_and_replay) perftest_start_and_check_nttcp $primary_host $secondary_host
                                  ;;
                                 *) :
                                 ;;
    esac

    perftest_do_${perftest_action} $primary_host $secondary_host $res \
                                            $perftest_parallel_writer \
                                            $perftest_result_type \
                                            ${#resource_name_list[*]}
    perftest_finish $secondary_host
}

function perftest_finish
{
    local primary_host=${global_host_list[0]}
    local secondary_host=${global_host_list[1]}
    perftest_stop_nttcp $secondary_host
}

function perftest_stop_nttcp
{
    local secondary_host=$1
    local nttcp_pid rc
    for i in "kill" "check"; do
        lib_vmsg "  searching nttcp pid on $secondary_host"
        nttcp_pid=$(lib_remote_idfile $secondary_host \
                             'pgrep -f "'"$perftest_nttcp_start_cmd"'"')
        rc=$?
        if [ $rc -eq 0 ]; then
            lib_vmsg "  found pid = $nttcp_pid"
            if [ "$i" = "kill" ]; then
                lib_vmsg "  trying to kill nttcp $nttcp_pid on $secondary_host"
                lib_remote_idfile $secondary_host "kill -9 $nttcp_pid"
                sleep 1
            else
                lib_vmsg "  could not kill nttcp $nttcp_pid on $secondary_host"
                break
            fi
        else
            if [ "$i" = "kill" ]; then
                lib_vmsg "  no process $perftest_nttcp_start_cmd running"
                break
            else
                lib_vmsg "  killed process (pid=$nttcp_pid) $perftest_nttcp_start_cmd"
            fi
        fi
        sleep 1
    done
}

function perftest_start_and_check_nttcp
{
    local primary_host=$1 secondary_host=$2
    local net_throughput
    local cmd="nttcp -p $perftest_nttcp_port -r -i &"
    local host i
    if [ ${perftest_check_net_throughput:-0} -eq 0 ]; then
        lib_exit 1 "perftest_check_net_throughput not set or 0"
    fi
    for host in $primary_host $secondary_host; do
        lib_vmsg "  checking whether nttcp is installed on $host"
        lib_remote_idfile $host "type nttcp" || \
                        lib_exit 1 "nttcp not installed on $host"
    done
    for i in "start" "check"; do
        if ! lib_remote_idfile $secondary_host \
                               "pgrep -f '"$perftest_nttcp_start_cmd"'"
        then
            if [ "$i" = "start" ]; then
                lib_vmsg "  starting nttcp receiver on $secondary_host"
                lib_remote_idfile $secondary_host "$perftest_nttcp_start_cmd" &
            else
                lib_vmsg "  could not start receiver on $secondary_host"
                return
            fi
        else
            if [ "$i" = "start" ]; then
                lib_vmsg "  nttcp $perftest_nttcp_start_cmd already running on $secondary_host"
                break
            else
                lib_vmsg "  nttcp $perftest_nttcp_start_cmd started on $secondary_host"
            fi
        fi
        sleep 1
    done
    main_error_recovery_functions["perftest_stop_nttcp"]="$secondary_host"
    perftest_check_tcp_connection $primary_host $secondary_host "net_throughput"
}

function perftest_check_tcp_connection
{
    [ $# -eq 3 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local primary_host=$1 secondary_host=$2 varname_throughput=$3
    local cmd="nttcp -n16384 -f  %9b%8.2rt%8.2ct%15.4rbr%15.4cbr%8c%10.2rcr%10.2ccr -p $perftest_nttcp_port -T $secondary_host"
    local nttcp_out mbit_per_second
    if [ ${perftest_check_net_throughput:-0} -eq 0 ]; then
        lib_exit 1 "perftest_check_net_throughput not set or 0"
    fi
    lib_vmsg "  checking tcp via nttcp on $primary_host"
    nttcp_out=($(lib_remote_idfile $primary_host "$cmd"))
    echo "${nttcp_out[*]}"
    # nttcp_out looks like
    #      Bytes  Real s   CPU s    Real-MBit/s     CPU-MBit/s   Calls  Real-C/s   CPU-C/s
    # l 67108864    0.55    0.03       971.1935     17895.6971   16384  29638.47 546133.33
    # 1 67108864    0.62    0.09       862.4709      5965.2324   20383  32744.83 226477.78
    # and we need the 971 Mbit/s
    mbit_per_second=${nttcp_out[14]}
    eval $varname_throughput=${mbit_per_second%.*}
}



function perftest_remove_data_file
{
    local data_file=$1
    shift
    local hosts="$@" host
    for host in $hosts; do
        lib_vmsg "  removing $host:$data_file"
        lib_remote_idfile $host "rm -f $data_file" || lib_exit 1
    done
}

function perftest_do_write
{
    [ $# -eq 6 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    lib_vmsg "  executing ${FUNCNAME[0]}"
    local primary_host=$1 secondary_host=$2 res=$3
    local parallel_writer=$4 result_type=$5 no_resources=$6
    local  writer_pid writer_script write_count writer_start
    local  writer_rate
    writer_start=$(date +'%s')
    lib_rw_start_writing_data_device $primary_host "writer_pid" \
                                     "writer_script" 0 0 $res ""
    lib_vmsg "  sleep $perftest_write_time"
    sleep $perftest_write_time
    lib_rw_stop_writing_data_device $primary_host $writer_script "write_count"
    main_error_recovery_functions["lib_rw_stop_scripts"]=
    writer_rate=$(perftest_get_rate_per_minute $writer_start $(date +'%s') \
                                               $write_count)
    main_error_recovery_functions["lib_rw_stop_scripts"]=
    mount_umount_data_device_all
    lib_vmsg "  ${FUNCNAME[0]}: do_write rate: $writer_rate"
    perftest_check_result $writer_rate $primary_host "write" $parallel_writer \
                          $result_type $no_resources \
                          $(perftest_get_write_subcase_id) -1
}

function perftest_get_rate_per_minute
{
    [ $# -eq 3 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local start=$1 end=$2 count=$3
    echo $(( (60 * $count ) / ($end - $start) ))
}

function perftest_via_rsync
{
    local secondary_host=$1 primary_host=$2 data_file=$3
    local varname_time_waited=$4
    local start=$(date +'%s') time_waited

    perftest_do_rsync $secondary_host $primary_host $data_file

    time_waited=$(($(date +'%s') - $start))
    eval $varname_time_waited=$time_waited
}

function perftest_do_rsync
{
    local secondary_host=$1 primary_host=$2 data_file=$3
    lib_vmsg "  syncing $primary_host:$data_file to $secondary_host"
    lib_remote_idfile $secondary_host \
            "rsync -av -e ssh root@$primary_host:$data_file $data_file" || \
                                                                lib_exit 1
}

function perftest_start_parallel_writer
{
    [ $# -eq 5 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local host=$1 varname_writer_start=$2 varname_writer_pid=$3
    local varname_writer_script=$4 res=$5
    mount_mount_data_device $host $res
    eval $varname_writer_start=$(date +'%s')
    lib_rw_start_writing_data_device $host $varname_writer_pid \
                                     $varname_writer_script 0 0 $res ""
}

function perftest_finish_parallel_writer
{
    [ $# -eq 6 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local host=$1 writer_script=$2 writer_start=$3
    local action=$4 no_resources=$5 subcase_id="$6"
    local write_count writer_rate
    local caller="${BASH_SOURCE[1]}:${FUNCNAME[1]}:${BASH_LINENO[0]}"

    lib_rw_stop_writing_data_device $host $writer_script "write_count"
    main_error_recovery_functions["lib_rw_stop_scripts"]=
    writer_rate=$(perftest_get_rate_per_minute $writer_start $(date +'%s') \
                                               $write_count)
    main_error_recovery_functions["lib_rw_stop_scripts"]=
    lib_vmsg "  $caller: do_write rate: $writer_rate"
    perftest_check_result $writer_rate $host write_while_$action 0 \
                          "loops_per_min" $no_resources "$subcase_id" -1

    mount_umount_data_device_all
}

function perftest_via_mars_sync
{
    [ $# -eq 8 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local primary_host=$1 secondary_host=$2 res=$3 dev=$4
    local parallel_writer=$5 result_type=$6 no_resources=$7 subcase_id=$8
    local synctime net_throughput
    local start_sync writer_pid writer_script writer_start

    marsadm_do_cmd $secondary_host "invalidate" $res || lib_exit 1

    
    if [ $parallel_writer -eq 1 ]; then
        writer_start=$(date +'%s')
        perftest_start_parallel_writer $primary_host "writer_start" \
                                       "writer_pid" "writer_script" $res
    fi

    marsadm_do_cmd $secondary_host "up" $res || lib_exit 1

    lib_wait_until_action_stops "syncstatus" $secondary_host $res \
                                  $perftest_maxtime_sync \
                                  $perftest_time_constant_sync \
                                  "synctime" 1 "net_throughput"

    perftest_check_result $synctime $secondary_host $perftest_action \
                          $parallel_writer "time" $no_resources "$subcase_id" $net_throughput

    if [ $parallel_writer -eq 1 ]; then
        perftest_finish_parallel_writer $primary_host $writer_script \
                                        $writer_start $perftest_action \
                                        $no_resources "$subcase_id"
        lib_vmsg "  recreating all resources"
        resource_recreate_all
        
    else
        lib_rw_compare_checksums $primary_host $secondary_host $res 0 "" ""
    fi
}

function perftest_generate_data_file
{
    [ $# -eq 5 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local primary_host=$1 secondary_host=$2 dev=$3 dev_size=$4
    local data_file=$5 file_size_in_kb=$(($dev_size * 1024 * 1024))
    local host

    lib_vmsg "  generating file $primary_host:$data_file ($file_size_in_kb KB) from $dev"
    lib_remote_idfile $primary_host \
            "dd if=$dev of=$data_file bs=1024 count=$file_size_in_kb" || \
                                                            lib_exit 1
    perftest_do_rsync $secondary_host $primary_host $data_file

    for host in $primary_host $secondary_host; do
        lib_remote_idfile $host "ls -l --full-time $data_file" || lib_exit 1
    done
}

function perftest_sysctrl_sync_modus
{
    local sync_mode="$1"
    shift
    local hosts="$@" host
    local mars_fast_sync_mode
    case "$sync_mode" in # (((
        fast_sync) mars_fast_sync_mode=1;;
        rsync|no_fast_sync) mars_fast_sync_mode=0;;
        *) lib_exit 1 "invalid sync_mode $sync_mode";;
    esac
    for host in $hosts; do
        lib_vmsg "  setting fast sync mode to $mars_fast_sync_mode on $host"
        lib_remote_idfile $host \
               "echo $mars_fast_sync_mode > $perftest_sync_mode_proc_file" \
                                                            || lib_exit 1
    done
}

function perftest_patch_data_device
{
    [ $# -eq 5 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local host=$1 dev=$2 dev_size_in_kb=$(($3 * 1024 * 1024))
    local patch_length_in_kb=$4 no_of_patches=$5
    local offset=0 bs=1024 remaining=$dev_size_in_kb

    while [ $offset -lt $((dev_size_in_kb - $patch_length_in_kb)) ]; do
        lib_vmsg "  patching $dev at $offset KB with $patch_length_in_kb KB"
        lib_remote_idfile $host \
            "yes :$offset: | dd of=$dev bs=$bs skip=$offset count=$patch_length_in_kb" || lib_exit 1
        offset=$(($offset + ($dev_size_in_kb / $no_of_patches)))
    done
}

function perftest_prepare_sync
{
    lib_vmsg "  executing ${FUNCNAME[0]}"
    local primary_host=$1 secondary_host=$2 res=$3
    local dev=$(lv_config_get_lv_device $res)
    local dev_size=$(lv_config_get_lv_size_from_name $res)
    local time_waited

    lib_wait_for_initial_end_of_sync $primary_host $secondary_host $res \
                                     $resource_maxtime_initial_sync \
                                     $resource_time_constant_initial_sync \
                                     "time_waited"
    lib_vmsg "  ${FUNCNAME[0]}: sync time: $time_waited"


    if [ "$perftest_sync_mode" != "rsync"  ]; then
        perftest_sysctrl_sync_modus $perftest_sync_mode $primary_host \
                                    $secondary_host
    else
        perftest_generate_data_file $primary_host $secondary_host $dev \
                                        $dev_size $perftest_data_file
    fi
}

function perftest_prepare_replay
{
    [ $# -eq 6 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    lib_vmsg "  executing ${FUNCNAME[0]}"
    local primary_host=$1 secondary_host=$2 res=$3
    local parallel_writer=$4 result_type=$5 no_resources=$6
    local data_dev=$(resource_get_data_device $res)
    local logfile length_logfile time_waited net_throughput

    perftest_check_and_get_required_result $secondary_host "replay" \
                            $parallel_writer $result_type \
                            $no_resources $perftest_logfile_size_in_gb >/dev/null \
                                                                || lib_exit 1

    perftest_prepare_resource $res $secondary_host

    marsadm_do_cmd $secondary_host "pause-replay" $res || lib_exit 1

    perftest_write_to_device $primary_host $res $data_dev $perftest_data_in_gb_to_write

    lib_wait_until_fetch_stops "perftest" $secondary_host $primary_host $res \
                               "logfile" "length_logfile" "time_waited" 0 \
                               "net_throughput"
    lib_vmsg "  ${FUNCNAME[0]}: fetch time: $time_waited"
    if [ $(lib_rw_round_to_gb $length_logfile) -ne $$perftest_logfile_size_in_gb ]
    then
        lib_exit 1 "req. logfile length = $$perftest_logfile_size_in_gb != $(lib_rw_round_to_gb $length_logfile) = act. logfile length"
    fi
    marsadm_do_cmd $secondary_host "disconnect" $res || lib_exit 1

}

function perftest_do_replay
{
    [ $# -eq 6 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    lib_vmsg "  executing ${FUNCNAME[0]}"
    local primary_host=$1 secondary_host=$2 res=$3
    local parallel_writer=$4 result_type=$5 no_resources=$6
    local time_waited net_throughput
    local writer_start writer_pid writer_script

    if [ $parallel_writer -eq 1 ]; then
        writer_start=$(date +'%s')
        perftest_start_parallel_writer $primary_host "writer_start" \
                                       "writer_pid" "writer_script" $res
    fi

    marsadm_do_cmd $secondary_host "resume-replay" $res || lib_exit 1

    lib_wait_until_action_stops "replay" $secondary_host $res \
                                  $perftest_maxtime_replay \
                                  $perftest_time_constant_replay "time_waited" \
                                  0 "net_throughput"
    lib_vmsg "  ${FUNCNAME[0]}: do_$perftest_action time: $time_waited"

    perftest_check_result $time_waited $secondary_host $perftest_action \
                          $parallel_writer $result_type $no_resources \
                          $perftest_logfile_size_in_gb -1
    if [ $parallel_writer -eq 1 ]; then
        perftest_finish_parallel_writer $primary_host $writer_script \
                                        $writer_start $perftest_action \
                                        $no_resources $perftest_logfile_size_in_gb
    fi
}

function perftest_prepare_resource
{
    local res=$1 secondary_host=$2
    resource_mount_mars_and_rm_resource_dir_all $res
    cluster_remove_debugfiles $secondary_host
    cluster_create_debugfiles $secondary_host
    resource_run_first
    marsview_wait_for_state $secondary_host $res "disk" "Uptodate" \
                            $perftest_maxtime_state_constant || lib_exit 1
}

function perftest_prepare_fetch
{
    perftest_prepare_fetch_or_fetch_and_replay "$@"
}

function perftest_prepare_fetch_and_replay
{
    perftest_prepare_fetch_or_fetch_and_replay "$@"
}

function perftest_do_fetch
{
    perftest_do_fetch_or_fetch_and_replay "$@"
}

function perftest_do_fetch_and_replay
{
    perftest_do_fetch_or_fetch_and_replay "$@"
}

function perftest_prepare_fetch_or_fetch_and_replay
{
    [ $# -eq 6 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    lib_vmsg "  executing ${FUNCNAME[0]}"
    local primary_host=$1 secondary_host=$2 res=$3
    local parallel_writer=$4 result_type=$5 no_resources=$6
    local data_dev=$(resource_get_data_device $res)
    local logfile logfile length_logfile

    perftest_check_and_get_required_result $secondary_host $perftest_action \
                            $parallel_writer $result_type \
                            $no_resources $perftest_logfile_size_in_gb >/dev/null \
                                                                || lib_exit 1

    perftest_prepare_resource $res $secondary_host

    marsadm_do_cmd $secondary_host "pause-replay" $res || lib_exit 1
    marsadm_do_cmd $secondary_host "disconnect" $res || lib_exit 1

    perftest_write_to_device $primary_host $res $data_dev $perftest_data_in_gb_to_write

    perftest_check_length_last_logfile $primary_host $res $primary_host \
                                       $perftest_logfile_size_in_gb

}

function perftest_get_length_last_logfile
{
    local host=$1 res=$2 primary_host=$3
    local length_logfile
    logfile=$(marsadm_get_last_logfile $host $res $primary_host) || lib_exit 1
    length_logfile=$(file_handling_get_file_length $host $logfile) || lib_exit 1
    echo $length_logfile
}

function perftest_check_length_last_logfile
{
    [ $# -eq 4 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local host=$1 res=$2 primary_host=$3 logfile_size_in_gb_req=$4
    local length_logfile
                                      
    length_logfile=$(perftest_get_length_last_logfile $host $res $primary_host)

    if [ $(lib_rw_round_to_gb $length_logfile) -ne $logfile_size_in_gb_req ]; then
        lib_exit 1 "req. logfile length = $logfile_size_in_gb_req != $(lib_rw_round_to_gb $length_logfile) = act. logfile length"
    fi
}

function perftest_do_fetch_or_fetch_and_replay
{
    [ $# -eq 6 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    lib_vmsg "  executing ${FUNCNAME[0]}"
    local primary_host=$1 secondary_host=$2 res=$3
    local parallel_writer=$4 result_type=$5 no_resources=$6
    local logfile length_logfile time_waited net_throughput
    local last_logfile_primary last_logfile_length_primary
    local writer_start writer_pid writer_script

    # with parallel writing, fetch will never stop. Though we take the time
    # until the actually last logfile has been fetched
    if [ $parallel_writer -eq 1 ]; then
        last_logfile_primary=$(marsadm_get_last_logfile $primary_host $res \
                               $primary_host) || lib_exit 1
        last_logfile_length_primary=$(file_handling_get_file_length \
                                      $primary_host $last_logfile_primary) \
                                                                || lib_exit 1
        lib_vmsg "  last logfile $primary_host:$last_logfile_primary has length $last_logfile_length_primary"

        writer_start=$(date +'%s')
        perftest_start_parallel_writer $primary_host "writer_start" \
                                       "writer_pid" "writer_script" $res
    fi

    marsadm_do_cmd $secondary_host "connect" $res || lib_exit 1
    if [ $perftest_action = "fetch_and_replay" ]; then
        marsadm_do_cmd $secondary_host "resume-replay" $res || lib_exit 1
    fi

    if [ $parallel_writer -eq 0 ]; then
        lib_wait_until_fetch_stops "perftest" $secondary_host $primary_host \
                                   $res "logfile" "length_logfile" \
                                   "time_waited" 1 "net_throughput"

        file_handling_check_equality_of_file_lengths $logfile $primary_host \
                                                     $secondary_host \
                                                     $length_logfile
    else
        lib_wait_until_logfile_has_length $secondary_host \
                                          $last_logfile_primary \
                                          $last_logfile_length_primary \
                                          "time_waited" \
                                          $perftest_maxtime_fetch 1 \
                                          "net_throughput"
        if [ $perftest_action = "fetch_and_replay" ]; then
            lib_wait_until_replay_has_reached_length $secondary_host $res  $last_logfile_primary \
                                                    $last_logfile_length_primary \
                                                    $perftest_wait_for_replay_to_stop_after_fetch_end
        fi

    fi

    lib_vmsg "  ${FUNCNAME[0]}: do_fetch time: $time_waited"

    perftest_check_result $time_waited $secondary_host $perftest_action \
                          $parallel_writer $result_type $no_resources \
                          $perftest_logfile_size_in_gb $net_throughput

    if [ $parallel_writer -eq 1 ]; then
        perftest_finish_parallel_writer $primary_host $writer_script \
                                        $writer_start $perftest_action \
                                        $no_resources $perftest_logfile_size_in_gb
    fi
}

function perftest_get_result_index
{
    [ $# -eq 6 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local host=$1 action=$2 parallel_writer=$3 result_type=$4 no_resources=$5
    local subcase_id="$6"
    echo "$host,$action,$parallel_writer,$result_type,$no_resources,$subcase_id"
}

function perftest_check_and_get_required_result
{
    [ $# -eq 6 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local host=$1 action=$2 parallel_writer=$3 result_type=$4 no_resources=$5
    local subcase_id="$6"
    local result_index="$(perftest_get_result_index $host $action \
                                      $parallel_writer $result_type \
                                      $no_resources $subcase_id)"
    if [ -z "${perftest_required_result_list[$result_index]}" ]; then
        lib_exit 1 "no value in perftest_required_result_list for index $result_index"
    fi
    echo ${perftest_required_result_list[$result_index]}
}

function perftest_check_result
{
    [ $# -eq 8 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local act_result=$1
    local host=$2 action=$3 parallel_writer=$4 result_type=$5 no_resources=$6
    local subcase_id="$7" net_throughput=$8
    local req_result req_result_string act_diff_percentage max_diff_percentage
    req_result_string=$(perftest_check_and_get_required_result $host $action \
                                     $parallel_writer $result_type \
                                     $no_resources $subcase_id) \
                                                                || lib_exit 1
    req_result=${req_result_string%,*}
    max_diff_percentage=${req_result_string#*,}
    act_diff_percentage=$(( (($act_result - $req_result) * 100 ) / $req_result ))
    lib_vmsg "  checking result $act_result for index $(perftest_get_result_index \
                                                $host $action $parallel_writer \
                                                $result_type \
                                                $no_resources \
                                            $subcase_id), req. = $req_result max_diff = $max_diff_percentage%,  act. diff percentage = $act_diff_percentage%, net rate = $net_throughput"
    if [ $act_diff_percentage -lt -$max_diff_percentage \
         -o $act_diff_percentage -gt $max_diff_percentage ]
    then
        echo "$perftest_errortag_result_out_of_bounds: act. result $act_result differs more than $max_diff_percentage% from $req_result" >&2
    fi
}

function perftest_write_to_device
{
    local host=$1 res=$2 dev=$3 data_in_gb_to_write=$4
    local bs=1024 dd_count=$((1024*1024))

    lib_vmsg "  writing $data_in_gb_to_write GB to $host:$dev"
    for i in $(seq 1 1 $data_in_gb_to_write); do
        lib_remote_idfile $host \
                          'yes $(printf "%0.1024d" '$i') | dd of='"$dev"' bs='"$bs"' count='$dd_count'' \
                                                                                            || lib_exit 1
    done                                                                                                
}

function perftest_get_sync_subcase_id
{
    local no_of_patches=$1 patch_length_in_kb=$2 sync_mode=$3
    echo "$no_of_patches:$patch_length_in_kb:$sync_mode"
}

function perftest_do_sync
{
    [ $# -eq 6 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    lib_vmsg "  executing ${FUNCNAME[0]}"
    local primary_host=$1 secondary_host=$2 res=$3
    local parallel_writer=$4 result_type=$5 no_resources=$6
    local dev=$(lv_config_get_lv_device $res)
    local dev_size=$(lv_config_get_lv_size_from_name $res)
    local i patch_length_in_kb no_of_patches
    local dev_to_patch

    if [ "$perftest_sync_mode" != "rsync"  ]; then
        dev_to_patch=$dev
    else
        dev_to_patch=$perftest_data_file
    fi

    for i in ${!perftest_patch_length_list[@]}; do
        no_of_patches=${perftest_number_of_patches_list[$i]}
        patch_length_in_kb=${perftest_patch_length_list[$i]}
        local subcase_id="$(perftest_get_sync_subcase_id $no_of_patches \
                                                         $patch_length_in_kb \
                                                         $perftest_sync_mode)"
        perftest_check_and_get_required_result $secondary_host "sync" \
                                     $parallel_writer $result_type \
                                     $no_resources "$subcase_id" >/dev/null \
                                                                || lib_exit 1
        lib_vmsg "  patchlength $patch_length_in_kb, no of patches $no_of_patches"
        if [ "$perftest_sync_mode" != "rsync"  ]; then
            marsadm_do_cmd $secondary_host "down" $res || lib_exit 1
        fi

        perftest_patch_data_device $secondary_host $dev_to_patch $dev_size \
                                   $patch_length_in_kb $no_of_patches

        if [ "$perftest_sync_mode" != "rsync"  ]; then

            perftest_via_mars_sync $primary_host $secondary_host $res $dev \
                                   $parallel_writer $result_type $no_resources \
                                   "$subcase_id"
        else
            perftest_via_rsync $secondary_host $primary_host \
                               $perftest_data_file "synctime" "$subcase_id"
        fi

    done

    if [ "$perftest_sync_mode" == "rsync"  ]; then
        perftest_remove_data_file $perftest_data_file $primary_host \
                                  $secondary_host
    fi
}

function perftest_get_write_subcase_id
{
    local subcase_id
    subcase_id="$perftest_write_time:$(lv_config_get_lv_size_from_name ${resource_name_list[0]}):$lib_rw_part_of_device_size_written_per_loop"
    if [ $perftest_division_mars_device_data_device -eq 1 ]; then
        subcase_id+=":$perftest_device_division"
    fi
    echo "$subcase_id"
}

function perftest_prepare_write
{
    [ $# -eq 6 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    lib_vmsg "  executing ${FUNCNAME[0]}"
    local primary_host=$1 secondary_host=$2 res=$3
    local parallel_writer=$4 result_type=$5 no_resources=$6
    local data_dev=$(resource_get_data_device $res)
    local logfile length_logfile time_waited

    if [ -z "$perftest_write_time" ]; then
        lib_exit 1 "perftest_write_time not set"
    fi

    perftest_check_and_get_required_result $primary_host "write" \
                                 $parallel_writer $result_type \
                                 $no_resources \
                                 $(perftest_get_write_subcase_id) >/dev/null \
                                                                || lib_exit 1

    perftest_prepare_resource $res $secondary_host
    mount_mount_data_device $primary_host $res
    resource_clear_data_device $primary_host $res
    if [ $perftest_division_mars_device_data_device -eq 1 ]; then
        perftest_switch_bbu_cache $primary_host
    fi
}

function perftest_switch_bbu_cache
{
    local host=$1 cmd
    case $perftest_device_division in # (((
        separated_and_mars_dev_without_bbu_cache)
                    lib_vmsg "  disabling bbu cache on $host"
                    for cmd in "${perftest_bbu_disable_cmd_list[@]}"; do
                        lib_remote_idfile $host $cmd || lib_exit 1
                    done
                    ;;
        separated_and_mars_dev_with_bbu_cache)
                    lib_vmsg "  enabling bbu cache on $host"
                    for cmd in "${perftest_bbu_enable_cmd_list[@]}"; do
                        lib_remote_idfile $host $cmd || lib_exit 1
                    done
                    ;;
        same_controller) :
                    ;;
        *) lib_exit 1 "invalid value $perftest_device_division for perftest_device_division in"
                    ;;
    esac
    for cmd in "${perftest_bbu_show_cmd_list[@]}"; do
        lib_remote_idfile $host $cmd || lib_exit 1
    done
}
