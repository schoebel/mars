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

function net_run
{
    local primary_host=${global_host_list[0]}
    local secondary_host="${global_host_list[1]}"
    local res=${resource_name_list[0]}
    local dev=$(lv_config_get_lv_device $res)
    local writer_pid writer_script write_count

    net_check_variables

    net_do_impact_cmd $primary_host "check_off" "remote_host=$secondary_host"

    mount_mount_data_device $primary_host $res
    resource_clear_data_device $primary_host $res
 
    lib_rw_start_writing_data_device $primary_host "writer_pid" \
                                     "writer_script"  0 1 $res ""

    sleep $net_time_data_dev_writer

    net_do_impact_cmd $primary_host "on" "remote_host=$secondary_host"

    sleep $net_time_data_dev_writer

    net_do_impact_cmd $primary_host "off" "remote_host=$secondary_host"

    lib_rw_stop_writing_data_device $primary_host $writer_script "write_count"
    main_error_recovery_functions["lib_rw_stop_scripts"]=

    mount_umount_data_device $primary_host $res
    lib_wait_for_secondary_to_become_uptodate_and_cmp_cksums "net" \
                                    $secondary_host $primary_host $res $dev 0
}

function net_do_impact_cmd
{
    local host=$1 array_index="$2" replace_expression="$3"
    local cmd="${net_impact_cmd[$array_index]}"
    local pattern="${replace_expression%=*}" replace="${replace_expression#*=}"
    local rc_req=0 check_array_index var
    local maxtime_retries=1 waited=0
    local rc

    if [ -z "$cmd" ]; then
        lib_exit 1 "no value to index $array_index in array net_impact_cmd"
    fi
    for var in pattern replace; do
        local x
        eval x='$'$var
        if [ -z "$x" ]; then
            lib_exit 1 "cannot determine $var in replace_expression $replace_expression"
        fi
    done
    
    cmd="${cmd//$pattern/$replace}"


    case $array_index in #(((
        check*) rc_req=${net_impact_cmd[${array_index}_rc]}
                maxtime_retries=$net_maxtime_check_retries
              ;;
        on|off) check_array_index=check_$array_index
                if [ $array_index = "on" ]; then
                    main_error_recovery_functions["net_do_impact_cmd"]="$host off $replace_expression"
                else
                    main_error_recovery_functions["net_do_impact_cmd"]=
                fi
                    
              ;;
             *) lib_exit 1 "invalid array_index $array_index"
              ;;
    esac

    while true; do
        lib_vmsg "  executing on $host $cmd. Req. return code = $rc_req"
        lib_remote_idfile $host "$cmd"
        rc=$?
        if [ \( $rc -eq 0 -a $rc_req -eq 0  \) \
             -o \( $rc -ne 0 -a $rc_req -ne 0  \) ]
        then
            break
        fi
        lib_vmsg "  command $cmd on $host returned unexpectedly $rc (waited=$waited)"
        sleep 1
        let waited+=1
        if [ $waited -ge $maxtime_retries ]; then
            lib_exit 1 "maxwait $maxtime_retries exceeded"
        fi
    done
    if [ -n "$check_array_index" ];then
        net_do_impact_cmd $host $check_array_index "$replace_expression"
    fi
}

function net_check_variables
{
    local switch index
    
    for switch in "on" "off"; do
        for index in $switch check_$switch check_${switch}_rc; do
            if [ -z "${net_impact_cmd[$index]}" ]; then
                lib_exit 1 "net_impact_cmd[$index] not set"
            fi
        done
    done
}

function net_clear_iptables_all
{
    local host
    for host in "${global_host_list[@]}"; do
        lib_vmsg "  flushing iptables on $host"
        lib_remote_idfile $host "iptables -F" || lib_exit 1
    done
}
