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
    local primary_host=${main_host_list[0]}
    local secondary_host="${main_host_list[1]}"
    local res=${resource_name_list[0]}
    local dev=$(lv_config_get_lv_device $res)
    local writer_pid writer_script write_count

    net_check_variables

    # replace string remote_host with $secondary_host
    declare -A impact_cmd
    eval impact_cmd=(\
          $(for x in ${!net_impact_cmd[@]};do
              printf "[$x]='${net_impact_cmd[$x]//remote_host/$secondary_host}' ";
            done)\
         )
    
    net_do_impact_cmd $primary_host "impact_cmd" "check_off"

    mount_mount_data_device
    resource_clear_data_device $primary_host $res
 
    lib_rw_start_writing_data_device $primary_host "writer_pid" \
                                     "writer_script"  0 1 $res

    sleep $net_time_data_dev_writer

    net_do_impact_cmd $primary_host "impact_cmd" "on"

    sleep $net_time_data_dev_writer

    net_do_impact_cmd $primary_host "impact_cmd" "off"

    lib_rw_stop_writing_data_device $primary_host $writer_script "write_count"
    main_error_recovery_functions["lib_rw_stop_scripts"]=

    mount_umount_data_device $primary_host $res
    lib_wait_for_secondary_to_become_uptodate_and_cmp_cksums "net" \
                                    $secondary_host $primary_host $res $dev 0
}

function net_do_impact_cmd
{
    local host=$1 cmd_array_varname="$2" array_index="$3"
    local declare_string="$(declare -p $cmd_array_varname)"
    eval declare -A cmd_array="${declare_string#*$cmd_array_varname=}"
    local cmd="${cmd_array[$array_index]}"
    local rc_req=0 check_array_index

    case $array_index in #(((
        check*) rc_req=${cmd_array[${array_index}_rc]}
              ;;
        on|off) check_array_index=check_$array_index
                if [ $array_index = "on" ]; then
                    main_error_recovery_functions["net_do_impact_cmd"]="$host cmd_array off"
                else
                    main_error_recovery_functions["net_do_impact_cmd"]=
                fi
                    
              ;;
             *) lib_exit 1 "invalid array_index $array_index"
              ;;
    esac

    lib_vmsg "  executing on $host $cmd. Req. return code = $rc_req"
    lib_remote_idfile $host "$cmd"
    rc=$?
    if [ \( $rc -eq 0 -a $rc_req -ne 0  \) \
         -o \( $rc -ne 0 -a $rc_req -eq 0  \) ]
    then
        lib_exit 1 "command $impact_cmd on $host returned unexpectedly $rc"
    fi
    if [ -n "$check_array_index" ];then
        net_do_impact_cmd $host cmd_array $check_array_index
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

