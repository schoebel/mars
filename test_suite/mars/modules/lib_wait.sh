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

function lib_wait_until_logfile_has_length
{
    [ $# -eq 7 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local host=$1 logfile=$2 length_logfile=$3
    local varname_time_waited=$4 maxwait=$5 check_net_throughput=$6 varname_net_throughput="$7"
    local act_length
    local waited=0 start_time=$(date +'%s') end_time
    local my_net_throughput=0 net_throughput_sum=0 net_check_count=0

    lib_vmsg "  waiting for $host:$logfile to grow to $length_logfile"

    while true; do
        lib_vmsg "  get length of $host:$logfile"
        act_length=$(file_handling_get_file_length $secondary_host $logfile) \
                                                                || lib_exit 1
        if [ $act_length -ge $length_logfile ]; then
            end_time=$(date +'%s')
            break
        fi
        sleep 1
        let waited+=1
        lib_vmsg "  waited $waited for $logfile act = $act_length, req = $length_logfile"
        if [ $waited -eq $maxwait ]; then
            lib_exit 1 "maxwait $maxwait exceeded"
        fi
        if [ $check_net_throughput -eq 1 ]; then
            if [ $(( $waited % $perftest_check_net_throughput_intervall )) -eq 0 ]; then
                perftest_check_tcp_connection $primary_host $secondary_host \
                                              "my_net_throughput"
                let net_throughput_sum+=$my_net_throughput
                let net_check_count+=1
            fi
        fi
    done
    eval $varname_time_waited=$(($end_time - $start_time))
    if [ $check_net_throughput -eq 1 ]; then
        local rate
        if [ $net_check_count -eq 0 ]; then
            rate=0
        else
            rate=$(($net_throughput_sum / $net_check_count))
        fi
        eval $varname_net_throughput=$rate
    fi
}

function lib_wait_until_fetch_stops
{
    [ $# -eq 9 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local module=$1 secondary_host=$2 primary_host=$3 res=$4
    local varname_logfile=$5 varname_length_logfile=$6
    local varname_time_waited=$7 check_net_throughput=$8 varname_net_throughput="$9"
    local maxtime_fetch time_constant_fetch var v

    for var in maxtime_fetch time_constant_fetch; do
        eval $var='$'${module}_${var}
        eval v='$'$var
        if [ -z "$v" ]; then
            lib_exit 1 "variable $var not set"
        fi
    done

    lib_vmsg "  ${FUNCNAME[0]}: module=$module, maxtime_fetch=$maxtime_fetch, time_constant_fetch=$time_constant_fetch"
    lib_wait_internal_until_fetch_stops $secondary_host $res $primary_host \
                                $maxtime_fetch \
                                $time_constant_fetch \
                                $varname_logfile $varname_length_logfile \
                                $varname_time_waited \
                                $check_net_throughput "$varname_net_throughput"
}

function lib_wait_internal_until_fetch_stops
{
    [ $# -eq 10 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local secondary_host=$1 res=$2 primary_host=$3 maxwait=$4 inactive_wait=$5
    local varname_logfile=$6 varname_logfile_length=$7 varname_time_waited=$8
    local check_net_throughput=$9 varname_net_throughput="${10}"
    local inactive_waited=0 msg
    local my_logfile length file_and_length file_and_length_old="x"
    local waited=0 msg start_time=$(date +'%s') end_time
    local my_net_throughput=0 net_throughput_sum=0 net_check_count=0
    while [ $waited -lt $maxwait ]; do
        my_logfile=$(marsadm_get_last_logfile $secondary_host $res \
                     $primary_host) || lib_exit 1
        lib_vmsg "  get length of $secondary_host:$my_logfile"
        length=$(file_handling_get_file_length $secondary_host $my_logfile) \
                                                                || lib_exit 1
        file_and_length="$my_logfile:$length"
        if [ "$file_and_length" = "$file_and_length_old" ]; then
            if [ $inactive_waited -eq 0 ]; then
                end_time=$(date +'%s')
            fi
            let inactive_waited+=1
        else
            let inactive_waited=0
        fi
        if [ $inactive_waited -eq $inactive_wait ]; then
            break
        fi
        sleep 1
        let waited+=1
        msg="  waited $waited for $my_logfile act = $file_and_length, old = $file_and_length_old"
        lib_vmsg "$msg"
        if [ $check_net_throughput -eq 1 ]; then
            if [ $(( $waited % $perftest_check_net_throughput_intervall )) -eq 0 ]; then
                perftest_check_tcp_connection $primary_host $secondary_host \
                                              "my_net_throughput"
                let net_throughput_sum+=$my_net_throughput
                let net_check_count+=1
            fi
        fi

        file_and_length_old="$file_and_length"
    done
    if [ $waited -eq $maxwait ]; then
        lib_exit 1 "$msg"
    fi
    if [ $check_net_throughput -eq 1 ]; then
        local rate
        if [ $net_check_count -eq 0 ]; then
            rate=0
        else
            rate=$(($net_throughput_sum / $net_check_count))
        fi
        eval $varname_net_throughput=$rate
    fi
    eval $varname_logfile_length=$length
    eval $varname_logfile=$my_logfile
    eval $varname_time_waited=$(($end_time - $start_time))
}

# the value of the "action" (=$1) link will be used
# if it remains constant over $4 seconds the function returns success
# the time waited is returned in the variable, whichs name is given by $6
function lib_wait_until_action_stops
{
    [ $# -eq 8 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local action=$1 host=$2 res=$3 maxwait=$4 inactive_wait=$5
    local varname_time_waited=$6 check_net_throughput=$7
    local varname_net_throughput="$8"
    local waited=0 link_value link_value_old="x"
    local inactive_waited=0 msg start_time=$(date +'%s') end_time
    local link=$(lib_linktree_get_res_host_linkname $host $res $action)
    local my_net_throughput=0 net_throughput_sum=0 net_check_count=0
    while [ $waited -lt $maxwait ]; do
        link_value=$(lib_remote_idfile $host readlink $link) || \
                                        lib_exit 1 "cannot read link $link"
        if [ "$link_value" = "$link_value_old" ]; then
            if [ $inactive_waited -eq 0 ]; then
                end_time=$(date +'%s')
            fi
            let inactive_waited+=1
        else
            let inactive_waited=0
        fi
        if [ $inactive_waited -eq $inactive_wait ]; then
            break
        fi
        sleep 1
        let waited+=1
        msg="  waited $waited for $action to stop on $host. old = $link_value_old, act = $link_value"
        lib_vmsg "$msg"
        if [ $check_net_throughput -eq 1 ]; then
            if [ $(( $waited % $check_net_throughput )) -eq 0 ]; then
                perftest_check_tcp_connection $primary_host $secondary_host \
                                              "my_net_throughput"
                let net_throughput_sum+=$my_net_throughput
                let net_check_count+=1
            fi
        fi
        link_value_old="$link_value"
    done
    if [ $waited -eq $maxwait ]; then
        lib_exit 1 "$msg"
    fi
    eval $varname_time_waited=$(($end_time - $start_time))
    if [ $check_net_throughput -eq 1 ]; then
        local rate
        if [ $net_check_count -eq 0 ]; then
            rate=0
        else
            rate=$(($net_throughput_sum / $net_check_count))
        fi
        eval $varname_net_throughput=$rate
    fi
}

function lib_wait_for_initial_end_of_sync
{
    [ $# -eq 6 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local primary_host=$1 secondary_host=$2 res=$3 maxwait=$4 inactive_wait=$5
    local varname_time_waited=$6
    local net_throughput
    lib_wait_until_action_stops "syncstatus" $secondary_host $res $maxwait \
                                $inactive_wait $varname_time_waited 0 \
                                "net_throughput"
    # we use deliberately the same times to wait as we did for the sync
    # above. After the sync the replays should not last more than some
    # seconds
    local time_waited
    lib_wait_until_action_stops "replay" $primary_host $res \
                                $maxwait $inactive_wait "time_waited" 0 \
                                "net_throughput"
    lib_wait_until_action_stops "replay" $secondary_host $res \
                                $maxwait $inactive_wait "time_waited" 0 \
                                "net_throughput"
    # after sync disk state must be Outdated || Uptodate
    marsview_wait_for_state $secondary_host $res "disk" ".*date.*" \
                            $marsview_wait_for_state_time || lib_exit 1
}

function lib_wait_for_secondary_to_become_uptodate_and_cmp_cksums
{
    [ $# -eq 6 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local module_name=$1 secondary_host=$2 primary_host=$3 res=$4
    local dev=$5 dev_size_to_compare=$6
    local host role logfile length_logfile time_waited write_count
    local net_throughput mount_point

    local maxtime_apply time_constant_apply str var
    for str in "maxtime" "time_constant"; do
        var=${module_name}_${str}_apply
        if [ -z "$var" ]; then
            lib_exit 1 "  variable $var not set"
        fi
        eval ${str}_apply='$'$var
    done

    lib_wait_until_fetch_stops $module_name $secondary_host $primary_host $res \
                               "logfile" "length_logfile" "time_waited" 0 \
                               "net_throughput"
    lib_vmsg "  ${FUNCNAME[0]} called from ${FUNCNAME[1]}: fetch time: $time_waited"

    file_handling_check_equality_of_file_lengths $logfile $primary_host \
                                                 $secondary_host $length_logfile

    lib_wait_until_action_stops "replay" $secondary_host $res \
                                $maxtime_apply \
                                $time_constant_apply "time_waited" 0 \
                                "net_throughput"
    lib_wait_until_action_stops "replay" $primary_host $res \
                                $maxtime_apply \
                                $time_constant_apply "time_waited" 0 \
                                "net_throughput"
    lib_vmsg "  ${FUNCNAME[0]} called from ${FUNCNAME[1]}: apply time: $time_waited"

    lib_linktree_check_equality_and_correctness_of_replay_links $primary_host \
                                                    $secondary_host $res

    for role in "primary" "secondary"; do
        eval host='$'${role}_host
        marsview_wait_for_state $host $res "disk" "Uptodate" $marsview_wait_for_state_time || lib_exit 1
        marsview_wait_for_state $host $res "repl" "-SFA-" $marsview_wait_for_state_time || lib_exit 1
    done

    lib_rw_compare_checksums $primary_host $secondary_host $res $dev_size_to_compare "" ""
}

function lib_wait_until_apply_has_reached_length
{
    [ $# -eq 5 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local secondary_host=$1 res=$2 logfile=$3 req_applied_length=$4 maxwait=$5
    local link=$(lib_linktree_get_res_host_linkname $secondary_host $res "replay")
    local link_value waited=0 act_applied_length
    while true; do
        lib_vmsg "  get applied length of $secondary_host:$logfile"
        link_value=$(lib_remote_idfile $secondary_host readlink $link) \
                                                                || lib_exit 1 "cannot read link $link"
        link_value=(${link_value//,/ })
        act_applied_length=${link_value[1]}
        if ! expr "$act_applied_length" : '^[0-9][0-9]*$' >/dev/null; then
            lib_exit 1 "cannot determine applied length from link_value ${link[@]}"
        fi
        if [ $act_applied_length -ge $req_applied_length ]; then
            break
        fi
        sleep 1
        let waited+=1
        lib_vmsg "  waited $waited for apply of $logfile act = $act_applied_length, req = $req_applied_length"
        if [ $waited -eq $maxwait ]; then
            lib_exit 1 "maxwait $maxwait exceeded"
        fi
    done
}

function lib_wait_for_connection
{
    local host=$1 res=$2
    local waited=0
    while true; do
        if marsadm_do_cmd $host "wait-connect" $res; then
            break
        fi
        sleep 1
        let waited+=1
        lib_vmsg "  waited $waited for connection for res $res on $host"
        if [ $waited -eq $lib_wait_for_cluster_connection_max_wait ]; then
            lib_exit 1 \
                    "maxwait $lib_wait_for_cluster_connection_max_wait exceeded"
        fi
    done
}
