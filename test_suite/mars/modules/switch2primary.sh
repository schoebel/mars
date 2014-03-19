#!/bin/bash
# Copyright 2010-2014 Frank Liepold /  1&1 Internet AG
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

function switch2primary_run
{
    local primary_host=${global_host_list[0]}
    local secondary_host=${global_host_list[1]}
    local res=${resource_name_list[0]}
    local dev=$(lv_config_get_lv_device $res)
    local writer_pid writer_script write_count
    local time_waited rc count=0
    local host

    lib_wait_for_initial_end_of_sync $primary_host $secondary_host $res \
                                  $resource_maxtime_initial_sync \
                                  $switch2primary_time_constant_initial_sync \
                                  "time_waited"
    lib_vmsg "  ${FUNCNAME[0]}: sync time: $time_waited"

    mount_mount_data_device $primary_host $res
    resource_clear_data_device $primary_host $res

    lib_rw_start_writing_data_device $primary_host "writer_pid" \
                                     "writer_script" 0 0 $res ""

    if [ $switch2primary_force -eq 1 ]; then
        switch2primary_force $primary_host $secondary_host $res $writer_script
        return
    else
        lib_vmsg "  marsadm primary on $secondary_host must fail"
        marsadm_do_cmd $secondary_host "primary" "$res"
        rc=$?
        if [ $rc -eq 0 ]; then
            lib_exit 1 "$secondary_host must not become primary"
        fi
    fi

    lib_rw_stop_writing_data_device $primary_host $writer_script "write_count"
    lib_vmsg "  ${FUNCNAME[0]}: write_count: $write_count"
    main_error_recovery_functions["lib_rw_stop_scripts"]=

    count=0
    while true; do
        mount_umount_data_device_all
        rc=$?
        if [ $rc -ne 0 ]; then
            let count+=1
            sleep 1
            lib_vmsg "  umount data device failed $count times"
            if [ $count -eq \
                 $lib_rw_number_of_umount_retries_after_stopped_write ]
            then
                lib_exit 1 "max tries exceeded"
            fi
            continue
        fi
        break
    done

    marsadm_do_cmd $primary_host "secondary" "$res" || lib_exit 1

    count=0
    while true; do
        marsadm_do_cmd $secondary_host "primary" "$res"
        rc=$?
        if [ $rc -ne 0 ]; then
            let count+=1
            sleep 1
            lib_vmsg "  switch to primary failed $count times"
            if [ $count -eq $switch2primary_max_tries ]; then
                lib_exit 1 "max tries exceeded"
            fi
            continue
        fi
        break
    done

    for host in $primary_host $secondary_host; do
        marsview_wait_for_state $host $res "disk" "Uptodate" \
                                $switch2primary_maxtime_state_constant || \
                                                                    lib_exit 1
    done
    lib_rw_compare_checksums $primary_host $secondary_host $res 0 "" ""

    marsadm_do_cmd $secondary_host "secondary" "$res" || lib_exit 1
}

# we assume that the script writer_script is running on the primary_host
# the process flow in switch2primary_force is as follows:
# 
# - start writing mounted data dev orig_primary (already started, when we enter
#   this function)
# - logrotate and logdelete on orig_primary (if 
#   switch2primary_logrotate_orig_primary == 1)
# - destroy logs behind replay link (if
#      switch2primary_full_replay_not_possible == 1 and
#      switch2primary_orig_prim_equal_new_prim == 0)
# - stop writing and unmount data dev orig_primary (if
#   switch2primary_data_dev_in_use == 0)
# - cut network connection (if switch2primary_connected == 0)
# - marsadm --force primary on orig_secondary
#       this must fail if switch2primary_full_replay_not_possible == 1
#       in this case we leave and create the resource and should be primary
#       afterwards (see switch2primary_recreate_resource)
# - logrotate and logdelete on orig_primary (if 
#   switch2primary_logrotate_orig_primary == 1)
# - stop writing and unmount data device primary (if
#   switch2primary_data_dev_in_use == 1)
#
# If the network connection works
# ---- the replication should work now with interchanged roles if 
#      switch2primary_orig_prim_equal_new_prim = 0
# ---- the replication should work now with original roles if 
#      switch2primary_orig_prim_equal_new_prim = 0 and after 
#      marsadm primary on orig_primary
# Otherwise we should have a real split brain and should be able to write on
# both data devices. The process flow continues:
#
# - start writing both data devices
# - logrotate and logdelete on orig_primary (if switch2primary_logrotate_split_brain_orig_primary == 1)
# - logrotate and logdelete on orig_secondary (if switch2primary_logrotate_split_brain_orig_secondary == 1)
# - stop writing both data devices
# - recreate network connection (if switch2primary_connected == 0 and
#            switch2primary_reconnect_before_primary_cmd_on_new_primary = 1)
#
# Now we try to solve the split brain. See switch2primary_correct_split_brain.
function switch2primary_force
{
    [ $# -eq 4 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local orig_primary=$1 orig_secondary=$2 res=$3 writer_script=$4
    local write_count time_waited host logfile length_logfile net_throughput
    local new_primary new_secondary rc
    local timeout_opt
    local destroy_logfile=0
    if [ $switch2primary_orig_prim_equal_new_prim -ne 0 ]; then
        new_primary=$orig_primary
        new_secondary=$orig_secondary
    else
        new_primary=$orig_secondary
        new_secondary=$orig_primary
    fi
    if [ $switch2primary_full_replay_not_possible -eq 1 \
         -a $switch2primary_orig_prim_equal_new_prim -eq 0 ]
    then
        destroy_logfile=1
    fi
    lib_vmsg "  $switch2primary_flow_msg_prefix: initial situation: primary=$orig_primary, secondary=$orig_secondary, data device mounted and writing process running"
    lib_vmsg "  $switch2primary_flow_msg_prefix: target state: new_primary=$new_primary, new_secondary=$new_secondary"
    if [ $switch2primary_logrotate_orig_primary -eq 1 ]; then
        lib_vmsg "  $switch2primary_flow_msg_prefix: log-rotate/log-delete on $orig_primary"
        logrotate_loop $orig_primary $res 3 4
    fi
    if [ $destroy_logfile -eq 1 ]; then
        lib_vmsg "  $switch2primary_flow_msg_prefix: destroy logfile on $new_primary"
        switch2primary_destroy_log_after_replay_link $new_primary $res
        timeout_opt='--timeout=40' # we don't want to wait too long
                                   # for the failure of --force primary
    fi
    if [ $switch2primary_data_dev_in_use -eq 0 ]; then
        lib_vmsg "  $switch2primary_flow_msg_prefix: stop writing on $orig_primary and umount data device"
        switch2primary_stop_write_and_umount_data_device $orig_primary \
                                        $writer_script "write_count"
    fi
    if [ $switch2primary_connected -eq 0 ]; then
        lib_vmsg "  $switch2primary_flow_msg_prefix: cut network"
        net_do_impact_cmd $orig_secondary "on" "remote_host=$orig_primary"
    fi
    lib_vmsg "  $switch2primary_flow_msg_prefix: generating split brain"
    marsadm_do_cmd $orig_secondary "disconnect" "$res" || lib_exit 1
    marsadm_do_cmd $orig_secondary "primary --force" "$res $timeout_opt"
    rc=$?
    if [ $destroy_logfile -eq 0 -a $rc -ne 0 ]; then
        lib_exit 1 "marsadm primary --force failed unexpectedly"
    fi
    if [ $destroy_logfile -eq 1 ]; then
        if [ $rc -eq 0 ]; then
            lib_exit 1 "marsadm primary --force succeeded unexpectedly"
        fi
        lib_vmsg "  $switch2primary_flow_msg_prefix: recreating resource on $orig_secondary"
        switch2primary_recreate_resource $orig_secondary $res
    fi
    if [ $switch2primary_logrotate_orig_primary -eq 1 ]; then
        lib_vmsg "  $switch2primary_flow_msg_prefix: log-rotate/log-delete on $orig_primary"
        logrotate_loop $orig_primary $res 3 4
    fi
    if [ $switch2primary_data_dev_in_use -ne 0 ]; then
        lib_vmsg "  $switch2primary_flow_msg_prefix: stop writing on $orig_primary and umount data device"
        switch2primary_stop_write_and_umount_data_device $orig_primary \
                                        $writer_script "write_count"
    fi
    lib_vmsg "  ${FUNCNAME[0]}: write_count: $write_count"

    if [ $switch2primary_connected -eq 1 ]; then
        switch2primary_correct_split_brain $orig_primary $orig_secondary \
                                            $new_primary $new_secondary $res
        return
    fi

    lib_vmsg "  $switch2primary_flow_msg_prefix: check that both data devices can be written"
    switch2primary_write_data_devices $res $orig_primary \
                            $switch2primary_logrotate_split_brain_orig_primary \
                            $orig_secondary \
                            $switch2primary_logrotate_split_brain_orig_secondary

    if [ $switch2primary_connected -eq 0 \
         -a $switch2primary_reconnect_before_primary_cmd_on_new_primary -eq 1 ]
    then
        lib_vmsg "  $switch2primary_flow_msg_prefix: restore network"
        switch2primary_restore_resource_connection $orig_secondary \
                                                   $orig_primary $res 1
    fi

    switch2primary_correct_split_brain $orig_primary $orig_secondary \
                                       $new_primary $new_secondary $res

}

function switch2primary_restore_resource_connection
{
    local local_host=$1 remote_host=$2 res=$3 resource_joined=$4
    net_do_impact_cmd $local_host "off" "remote_host=$remote_host"
    if [ $resource_joined -eq 1 ]; then
        lib_wait_for_connection $local_host $res
    fi
}
 
function switch2primary_stop_write_and_umount_data_device
{
    local host=$1 writer_script=$2 varname_write_count=$3
    lib_rw_stop_writing_data_device $host $writer_script $varname_write_count
    main_error_recovery_functions["lib_rw_stop_scripts"]=
    mount_umount_data_device $host $res
}

function switch2primary_wait_for_first_own_logfile_on_new_primary
{
    local host=$1 res=$2
    local maxwait=60 waited=0
    while true;do
        local last_logfile=$(marsadm_get_last_logfile $host $res $host)
        if [ -n "$last_logfile" ]; then
            lib_vmsg "  found logfile $last_logfile on $host"
            break
        fi
        let waited+=1
        lib_vmsg "  waited $waited for own logfile to appear on $host"
        if [ $waited -ge $maxwait ]; then
            lib_exit 1 "maxwait $maxwait exceeded"
        fi
    done
}

# check whether write access to the data device causes writes to the logfiles
# parameters: <resource> <host_1> <logrotate_flag_1> 
#                        <host_2> <logrotate_flag_2> ...
function switch2primary_write_data_devices
{
    local res=$1 host
    declare -A logrotate_flags # hostname indexed array of flags whether a
                               # log-rotate should be done on the host
    shift
    while [ -n "$1" ]; do
        if [ -z "$2" ]; then
            lib_exit 1 "no logrotate flag given for host $1"
        fi
        if [ "$2" != "0" -a "$2" != "1" ]; then
            lib_exit 1 "invalid logrotate flag $2 for host $1"
        fi
        logrotate_flags[$1]=$2
        shift; shift
    done
    local data_dev=$(resource_get_data_device $res)
    local script=$switch2primary_write_script_prefix.$$
    local writer_script writer_pid write_count host
    declare -A last_logfile_old
    declare -A length_last_logfile_old
    # this script will be started
    echo '#/bin/bash
while true; do
    # filter dd standard messages (records in, records out) from stderr
    yes xyz | dd oflag=direct bs=4096 count=1000 of='$data_dev' status=noxfer 3>&2 2>&1 >&3 | grep -v records 3>&2 2>&1 >&3
    sleep 1
done' >$script
    for host in ${!logrotate_flags[*]}; do
        # all hosts must have a least one logfile
        last_logfile_old[$host]=$(marsadm_get_last_logfile $host $res $host) \
                                                                || lib_exit 1
        length_last_logfile_old[$host]=$(file_handling_get_file_length \
                                         $host ${last_logfile_old[$host]}) \
                                                                || lib_exit 1
        lib_vmsg "  last logfile:length on $host: ${last_logfile_old[$host]}:${length_last_logfile_old[$host]}"
        lib_start_script_remote_bg $host $script "writer_pid" "writer_script" \
                                   "no_rm"
        main_error_recovery_functions["lib_rw_stop_scripts"]+="$host $script "
    done
    rm -f $script || lib_exit 1
    for host in ${!logrotate_flags[*]}; do
        if [ ${logrotate_flags[$host]} -eq 1 ]; then
            logrotate_loop $host $res 3 2
        fi
    done
    for host in ${!logrotate_flags[*]}; do
        lib_rw_stop_one_script $host $script "write_count"
    done
    main_error_recovery_functions["lib_rw_stop_scripts"]=
    for host in ${!logrotate_flags[*]}; do
        local last_logfile length_logfile
        last_logfile=$(marsadm_get_last_logfile $host $res $host) || lib_exit 1
        length_last_logfile=$(file_handling_get_file_length \
                                       $host $last_logfile) || lib_exit 1
        lib_vmsg "  act. last logfile:length on $host: $last_logfile:$length_last_logfile"
        if [ $last_logfile = ${last_logfile_old[$host]} \
             -a $length_last_logfile -eq ${length_last_logfile_old[$host]} ]
        then
            lib_exit 1 "nothing written to logfiles on $host"
        fi
    done
}

function switch2primary_check_standalone_primary
{
    local primary_host=$1 res=$2
    lib_vmsg "  checking $primary_host as standalone primary"
    switch2primary_write_data_devices $res $primary_host 1
    marsview_wait_for_state $primary_host $res "disk" "Uptodate" \
                            $marsview_wait_for_state_time || lib_exit 1
}

function switch2primary_correct_split_brain
{
    [ $# -eq 5 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local orig_primary=$1 orig_secondary=$2 new_primary=$3 new_secondary=$4
    local res=$5
    local data_dev=$(resource_get_data_device $res)
    local lv_dev=$(lv_config_get_lv_device $res)
    local time_waited
    local network_cut=0
    if [ $switch2primary_connected -eq 0 \
         -a $switch2primary_reconnect_before_primary_cmd_on_new_primary -eq 0 ]
    then
        network_cut=1
    fi
    lib_vmsg "  $switch2primary_flow_msg_prefix: starting split brain correction, network_cut=$network_cut"
    marsadm_do_cmd $new_primary "disconnect" "$res" || lib_exit 1
    # Only to switch the designated primary. The device may not appear, though
    # we omit the usual check of post conditions via marsadm_do_cmd.
    lib_vmsg "  $switch2primary_flow_msg_prefix: special primary --force on $new_primary"
    lib_remote_idfile $new_primary "marsadm primary --timeout=240 --force $res" || lib_exit 1
    marsadm_do_cmd $new_primary "connect" "$res" || lib_exit 1
    # if the new_primary was recreated, the delete-resource in
    # switch2primary_recreate_resource destroys the resource on the
    # new_secondary. Thus two branches to restore the replication are needed
    if [ $switch2primary_full_replay_not_possible -eq 0 ]; then
        if [ $network_cut -eq 0 \
             -a $switch2primary_disconnect_before_leave_resource -eq 1 ]
        then
            lib_vmsg "  $switch2primary_flow_msg_prefix: cut network"
            net_do_impact_cmd $orig_secondary "on" "remote_host=$orig_primary"
            network_cut=1
        fi
        marsadm_do_cmd $new_secondary "down" "$res" || lib_exit 1
        marsadm_do_cmd $new_primary \
                     "leave-resource --force --host=$new_secondary" "$res" || \
                                                                    lib_exit 1
        echo "sleeping for propagation...."
        sleep 15
        marsadm_do_cmd $new_primary "log-purge-all --force" "$res" || lib_exit 1
    fi
    lib_vmsg "  $switch2primary_flow_msg_prefix: check whether new primary $new_primary works standalone"
    switch2primary_check_standalone_primary $new_primary $res
    if [ $network_cut -eq 1 ]; then
        lib_vmsg "  $switch2primary_flow_msg_prefix: restore network"
        switch2primary_restore_resource_connection $orig_secondary \
                                                   $orig_primary $res 0
        lib_vmsg "  $switch2primary_flow_msg_prefix: check whether new primary $new_primary works standalone"
        switch2primary_check_standalone_primary $new_primary $res
    fi

    # now do the restore work.....
    # we assume that the $new_secondary is physically usable again in some way.

    marsadm_do_cmd $new_secondary "log-purge-all --force" "$res" || lib_exit 1
    marsadm_do_cmd $new_secondary "join-resource --force" "$res $lv_dev" \
                                                            || lib_exit 1
    lib_vmsg "  $switch2primary_flow_msg_prefix: wait for end of sync on new secondary $new_secondary"
    lib_wait_for_initial_end_of_sync $new_primary $new_secondary $res \
                                     $resource_maxtime_initial_sync \
                                     $resource_time_constant_initial_sync \
                                     "time_waited"
    lib_vmsg  " $switch2primary_flow_msg_prefix: check equality of replay links"
    lib_linktree_check_equality_and_correctness_of_replay_links $new_primary \
                                                $new_secondary $res
    resource_check_replication $new_primary $new_secondary $res \
                               "$switch2primary_flow_msg_prefix: "
}

function switch2primary_destroy_log_after_replay_link
{
    local host=$1 res=$2 link link_val replay_offset
    local logfile length_logfile  time_waited
    lib_vmsg "  destroying log after replay link on $host"
    marsadm_do_cmd $host "pause-replay" "$res" || lib_exit 1
    lib_wait_until_action_stops "replay" $host $res \
                                  $switch2primary_maxtime_replay \
                                  $switch2primary_time_constant_replay \
                                  "time_waited" 0 ""
    logfile=$(lib_linktree_get_partial_value_from_replay_link \
               $host $res "logfilename") || lib_exit 1
    length_logfile=$(file_handling_get_file_length $host $logfile) || lib_exit 1
    replay_offset=$(lib_linktree_get_partial_value_from_replay_link \
               $host $res "replay_offset") || lib_exit 1
    if [ $replay_offset -ge $length_logfile ]; then
        lib_vmsg  "  logfile $logfile already fully applied on host $host"
        logfile=$(lib_linktree_get_next_logfile $logfile) || lib_exit 1
        replay_offset=0
    fi
    lib_vmsg "  destroy logfile $host:$logfile at offset $replay_offset"
    lib_remote_idfile $host "yes | dd bs=1 conv=notrunc seek=$replay_offset of=$logfile count=10000" || lib_exit 1
    marsadm_do_cmd $host "resume-replay" "$res" || lib_exit 1
}

function switch2primary_recreate_resource
{
    local host=$1 res=$2
    local res_dir=$(resource_get_resource_dir $res)
    local dev=$(lv_config_get_lv_device $res)
    lib_vmsg "  recreating resource $res on $host"
    marsadm_do_cmd $host "secondary" "$res" || lib_exit 1
    marsadm_do_cmd $host "down" "$res" || lib_exit 1
    marsadm_do_cmd $host "leave-resource" "$res" || lib_exit 1
    sleep 15
    marsadm_do_cmd $host "delete-resource --force" "$res" || lib_exit 1
    marsadm_do_cmd $host "create-resource --force" "$res $dev" || lib_exit 1
}
