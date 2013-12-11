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
                                  $resource_time_constant_initial_sync \
                                  "time_waited"
    lib_vmsg "  ${FUNCNAME[0]}: sync time: $time_waited"

    marsadm_do_cmd $primary_host "primary" "$res" || lib_exit 1

    mount_mount_data_device
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

function switch2primary_force
{
    [ $# -eq 4 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local primary_host=$1 secondary_host=$2 res=$3 writer_script=$4
    local write_count time_waited host logfile length_logfile net_throughput
#     # replace string remote_host with $secondary_host
#     declare -A impact_cmd
#     eval impact_cmd=(\
#           $(for x in ${!net_impact_cmd[@]};do
#               printf "[$x]='${net_impact_cmd[$x]//remote_host/$primary_host}' ";
#             done)\
#          )
#     lib_vmsg "sleep 10"
#     sleep 10
#     net_do_impact_cmd $host "impact_cmd" "off"
    marsadm_do_cmd $secondary_host "--force primary" "$res" || lib_exit 1
    lib_rw_stop_writing_data_device $primary_host $writer_script "write_count"
    lib_vmsg "  ${FUNCNAME[0]}: write_count: $write_count"
    main_error_recovery_functions["lib_rw_stop_scripts"]=
    lib_wait_until_fetch_stops "switch2primary" $secondary_host $primary_host \
                                $res "logfile" "length_logfile" "time_waited" \
                                0 "net_throughput"
    lib_vmsg "  ${FUNCNAME[0]}: fetch time: $time_waited"

    switch2primary_wait_for_first_own_logfile_on_new_primary $secondary_host \
                                                             $res
    for host in $primary_host $secondary_host; do
        switch2primary_check_write_to_logfiles $host $res
    done

    switch2primary_correct_split_brain $primary_host $secondary_host $res

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
function switch2primary_check_write_to_logfiles
{
    local host=$1 res=$2
    local length_logfile length_logfile_old
    local dev=$(resource_get_data_device $res)
    length_logfile_old=$(perftest_get_length_last_logfile $host $res $host)
    lib_vmsg " length last logfile on $host: $length_logfile_old"
    lib_remote_idfile $host \
                      "yes | dd oflag=direct bs=4096 count=1 of=$dev" || \
                                                            lib_exit 1
    length_logfile=$(perftest_get_length_last_logfile $host $res $host)
    lib_vmsg " length last logfile on $host: $length_logfile"
    if [ $length_logfile -eq $length_logfile_old ]; then
        lib_exit 1 "nothing written to logfiles on $host"
    fi
}

function switch2primary_correct_split_brain
{
    local host=$1 # the former primary
    local primary_host=$2 res=$3
    local dev=$(resource_get_data_device $res)
    local time_waited
    mount_umount_data_device $host $res
    marsadm_do_cmd $host "secondary" "$res" || lib_exit 1
    marsadm_do_cmd $primary_host "invalidate" "$res" || lib_exit 1
    lib_wait_for_initial_end_of_sync $primary_host $host $res \
                                     $resource_maxtime_initial_sync \
                                     $resource_time_constant_initial_sync \
                                     "time_waited"
    lib_vmsg "  write some data to $primary_host:$dev"
    lib_remote_idfile $primary_host \
                      "yes | dd oflag=direct bs=4096 count=1 of=$dev" || \
                                                            lib_exit 1
    lib_wait_for_secondary_to_become_uptodate_and_cmp_cksums "resource" \
                                            $host $primary_host \
                                            $res $dev 0
}
