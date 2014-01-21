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
    local primary_host=${main_host_list[0]}
    local secondary_host=${main_host_list[1]}
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
                                     "writer_script" 0 0 $res

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
#      switch2primary_full_apply_not_possible == 1 and
#      switch2primary_orig_prim_equal_new_prim == 0)
# - stop writing and unmount data dev orig_primary (if
#   switch2primary_data_dev_in_use == 0)
# - cut network connection (if switch2primary_connected == 0)
# - marsadm --force primary on orig_secondary
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
    local new_primary new_secondary
    if [ $switch2primary_orig_prim_equal_new_prim -ne 0 ]; then
        new_primary=$orig_primary
        new_secondary=$orig_secondary
    else
        new_primary=$orig_secondary
        new_secondary=$orig_primary
    fi
    if [ $switch2primary_logrotate_orig_primary -eq 1 ]; then
        logrotate_loop $orig_primary $res 3 4
    fi
    if [ $switch2primary_full_apply_not_possible -eq 1 \
         -a $switch2primary_orig_prim_equal_new_prim -eq 0 ]
    then
        switch2primary_destroy_log_after_replay_link $new_primary $res
    fi
    if [ $switch2primary_data_dev_in_use -eq 0 ]; then
        switch2primary_stop_write_and_umount_data_device $orig_primary \
                                        $writer_script "write_count"
    fi
    if [ $switch2primary_connected -eq 0 ]; then
        net_do_impact_cmd $orig_secondary "on" "remote_host=$orig_primary"
    fi
    marsadm_do_cmd $orig_secondary "disconnect" "$res" || lib_exit 1
    marsadm_do_cmd $orig_secondary "primary --force" "$res" || lib_exit 1
    if [ $switch2primary_logrotate_orig_primary -eq 1 ]; then
        logrotate_loop $orig_primary $res 3 4
    fi
    if [ $switch2primary_data_dev_in_use -ne 0 ]; then
        switch2primary_stop_write_and_umount_data_device $orig_primary \
                                        $writer_script "write_count"
    fi
    lib_vmsg "  ${FUNCNAME[0]}: write_count: $write_count"

    if [ $switch2primary_connected -eq 1 ]; then
        if [ $switch2primary_orig_prim_equal_new_prim -eq 1 ]; then
            marsadm_do_cmd $new_primary "primary" "$res" || lib_exit 1
        fi
        resource_check_replication $new_primary $new_secondary $res
        return
    fi

    switch2primary_write_data_devices $res $orig_primary \
                            $switch2primary_logrotate_split_brain_orig_primary \
                            $orig_secondary \
                            $switch2primary_logrotate_split_brain_orig_secondary

    if [ $switch2primary_connected -eq 0 \
         -a $switch2primary_reconnect_before_primary_cmd_on_new_primary -eq 1 ]
    then
        switch2primary_restore_resource_connection $orig_secondary \
                                                   $orig_primary $res
    fi

    switch2primary_correct_split_brain $orig_primary $orig_secondary \
                                       $new_primary $new_secondary $res

}

function switch2primary_restore_resource_connection
{
    local local_host=$1 remote_host=$2 res=$3
    net_do_impact_cmd $local_host "off" "remote_host=$remote_host"
    lib_wait_for_connection $local_host $res
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
    local time_waited
    marsadm_do_cmd $new_primary "connect" "$res" || lib_exit 1
    marsadm_do_cmd $new_primary "primary" "$res" || lib_exit 1
    switch2primary_check_standalone_primary $new_primary $res
    if [ $switch2primary_connected -eq 0 \
         -a $switch2primary_reconnect_before_primary_cmd_on_new_primary -eq 0 ]
    then
        switch2primary_restore_resource_connection $orig_secondary \
                                                   $orig_primary $res
        switch2primary_check_standalone_primary $new_primary $res
    fi

    if [ $switch2primary_activate_secondary_hardcore -eq 0 ]; then
        marsadm_do_cmd $new_secondary "invalidate" "$res" || lib_exit 1
        marsadm_do_cmd $new_secondary "connect" "$res" || lib_exit 1
    else
        local lv_dev=$(lv_config_get_lv_device $res)
        marsadm_do_cmd $new_secondary "down" "$res" || lib_exit 1
        marsadm_do_cmd $new_secondary "leave-resource --force" "$res" || \
                                                                    lib_exit 1
        marsadm_do_cmd $new_secondary "join-resource --force" "$res $lv_dev" \
                                                                || lib_exit 1
    fi
    lib_wait_for_initial_end_of_sync $new_primary $new_secondary $res \
                                     $resource_maxtime_initial_sync \
                                     $resource_time_constant_initial_sync \
                                     "time_waited"
    resource_check_replication $new_primary $new_secondary $res
}

function switch2primary_destroy_log_after_replay_link
{
    local host=$1 res=$2 link link_val replay_offset
    local logfile length_logfile 
    lib_vmsg "  destroying log after replay link on $host"
    marsadm_do_cmd $host "pause-replay" "$res" || lib_exit 1
    link="$(lib_linktree_get_res_host_linkname $host $res replay replay)" || \
                                                                    lib_exit 1
    link_val="$(lib_remote_idfile $host "readlink $link")" || lib_exit 1
    logfile=${resource_dir_list[$res]}/${link_val%%,*}
    length_logfile=$(file_handling_get_file_length $host $logfile) || lib_exit 1
    replay_offset=$(expr "$link_val" : '.*,\(.*\),.*')
    if [ -z "$replay_offset" ]; then
        lib_exit 1 "cannot determine replay offset from replay link value $link_val on host $host"
    fi
    if [ $replay_offset -ge $length_logfile ]; then
        lib_exit 1 "logfile $logfile already fully applied on host $host"
    fi
    lib_vmsg "  destroy logfile $host:$logfile at offset $replay_offset"
    lib_remote_idfile $host "yes | dd bs=1 conv=notrunc seek=$replay_offset of=$logfile count=10000" || lib_exit 1
    marsadm_do_cmd $host "resume-replay" "$res" || lib_exit 1
}
