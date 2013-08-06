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

    lib_wait_for_initial_end_of_sync $secondary_host $res \
                                  $resource_maxtime_initial_sync \
                                  $resource_time_constant_initial_sync \
                                  "time_waited"
    lib_vmsg "  ${FUNCNAME[0]}: sync time: $time_waited"

    marsadm_do_cmd $primary_host "primary" "$res" || lib_exit 1

    mount_mount_data_device

    lib_rw_start_writing_data_device "writer_pid" "writer_script" 0 0 $res

    lib_vmsg "  marsadm primary on $secondary_host must fail"
    marsadm_do_cmd $secondary_host "primary" "$res"
    rc=$?
    if [ $rc -eq 0 ]; then
        lib_exit 1 "$secondary_host must not become primary"
    fi

    lib_rw_stop_writing_data_device $writer_script "write_count"
    lib_vmsg "  ${FUNCNAME[0]}: write_count: $write_count"

    count=0
    while true; do
        mount_umount_data_device
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

    marsview_wait_for_state $secondary_host $res "disk" "Uptodate" \
                            $switch2primary_maxtime_state_constant || lib_exit 1
    lib_rw_compare_checksums $primary_host $secondary_host $dev 0 "" ""

    marsadm_do_cmd $secondary_host "secondary" "$res" || lib_exit 1
}

