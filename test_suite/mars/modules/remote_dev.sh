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


function remote_dev_run
{
    local primary_host=${global_host_list[0]}
    local secondary_host=${global_host_list[1]}
    local res=${resource_name_list[0]}
    local dev=$(lv_config_get_lv_device $res)
    local writer_pid writer_script write_count
    local log_rotate_pid log_rotate_script
    local log_delete_pid log_delete_script action

    mount_mount_data_device $primary_host $res
    resource_clear_data_device $primary_host $res

    cluster_remove_debugfiles $primary_host
    cluster_create_debugfiles $primary_host

    lib_rw_start_writing_data_device $primary_host "writer_pid" \
                                     "writer_script" 0 0 $res ""

    for action in "rotate" "delete"; do
        local sleep_time pid_varname script_varname
        eval sleep_time='$remote_dev_log_'$action'_sleep'
        pid_varname="log_${action}_pid"
        script_varname="log_${action}_script"
        logrotate_start_action_loop $primary_host $action $res \
                                    $sleep_time $pid_varname $script_varname
    done

    remote_dev_create_local_link_for_remote_device $secondary_host \
                                                   $primary_host $res

    lib_err_wait_for_error_messages $primary_host $lib_err_total_log_file \
                                "$remote_dev_errmsg_pattern" \
                                $remote_dev_number_errmsg_req \
                                $remote_dev_maxtime_to_wait_for_errmsg
                                       
    lib_err_check_nonexistence_of_other_error_messages $primary_host \
                                        $lib_err_total_log_file \
                                        "$remote_dev_errmsg_pattern"
    
    lib_rw_stop_scripts $primary_host $log_delete_script

    lib_rw_stop_scripts $primary_host $log_rotate_script

    lib_rw_stop_writing_data_device $primary_host $writer_script "write_count"
    main_error_recovery_functions["lib_rw_stop_scripts"]=

    local boot_label_name="${global_host_bootloader_label_list[$secondary_host]}"
    local mars_dev=$(lv_config_get_lv_device ${cluster_mars_dir_lv_name_list[$secondary_host]})
    crash_reboot $secondary_host "" $mars_dev $crash_maxtime_reboot \
                 $crash_maxtime_to_become_unreachable \
                 "$boot_label_name"
    remote_dev_remove_magic_links $secondary_host
}

function remote_dev_remove_magic_links
{
    local secondary_host=$1
    local host

    # to guarantee persistence of removal on all hosts
    resource_kill_all_scripts
    mount_umount_data_device_all
    cluster_rmmod_mars_all

    for host in "${global_host_list[@]}"; do
        local magic_link_pattern="$global_mars_directory/resource-*/$(remote_dev_get_magic_link_name $secondary_host)"
        lib_vmsg "  removing $magic_link_pattern on $host"
        lib_remote_idfile $host "rm $magic_link_pattern"
    done

    cluster_insert_mars_module_all
}

function remote_dev_get_magic_link_name
{
    local host=$1
    echo "_direct-001-${host}"
}

function remote_dev_create_local_link_for_remote_device
{
    [ $# -eq 3 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local local_host=$1 remote_host=$2 res=$3 
    local res_dir="${resource_dir_list[$res]}"
    local link="$res_dir/$(remote_dev_get_magic_link_name $local_host)"

    local link_value="${remote_dev_non_existant_file}@${remote_host},remote-floppy"
    
    lib_vmsg "  removing old link $link  on $local_host"
    lib_remote_idfile $local_host "rm -f $link" || lib_exit 1
    lib_vmsg "  creating link $link -> $link_value on $local_host"
    lib_remote_idfile $local_host "ln -s $link_value $link" || lib_exit 1
    main_error_recovery_functions["remote_dev_remove_magic_links"]="$secondary_host"
}

