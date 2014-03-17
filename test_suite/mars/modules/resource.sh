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

function resource_prepare
{
    local res
    resource_check_variables
    if [ $net_clear_iptables_in_prepare_phase -eq 1 ]; then
        net_clear_iptables_all
    fi
    resource_kill_all_scripts
    for res in ${lv_config_lv_name_list[@]}; do
        mount_umount_data_device_all $res
    done
    cluster_rmmod_mars_all
    cluster_clear_and_umount_mars_dir_all
    lv_config_recreate_logical_volumes 0
    cluster_clear_and_mount_mars_dir_all
    cluster_insert_mars_module_all
}

# assumes the following:
# - all logical volumes exist and have their correct sizes
# - /mars is mounted
# - exactly one resource
function resource_quick_prepare_first_resource
{
    local primary_host=${global_host_list[0]}
    local secondary_host=${global_host_list[1]}
    local res=${resource_name_list[0]}
    local dev="$(lv_config_get_lv_device $res)"
    local data_dev=$(resource_get_data_device $res)
    local waited
    if [ $net_clear_iptables_in_prepare_phase -eq 1 ]; then
        net_clear_iptables_all
    fi
    resource_kill_all_scripts
    cluster_rmmod_mars_all
    cluster_clear_and_mount_mars_dir_all
    cluster_insert_mars_module_all
    marsadm_do_cmd $primary_host "create-resource" "$res $dev" || lib_exit 1
    marsadm_do_cmd $primary_host "wait-resource" "$res is-device-on" || \
                                                                  lib_exit 1
    resource_check_data_device_after_create $primary_host $res
    lib_rw_remote_check_device_fs $primary_host $data_dev "xfs"
    marsadm_do_cmd $secondary_host "join-resource" "$res $dev" || lib_exit 1
}

function resource_check_variables
{
    if ! expr "${lv_config_lv_name_list[*]}" \
          : "\(\(.* \)*${resource_name_list[*]}\( .*\)*\$\)" >/dev/null
    then
        lib_exit 1 "resource_name_list = '${resource_name_list[*]}' is no substring of '${lv_config_lv_name_list[*]}' = lv_config_lv_name_list"
    fi
}

function resource_recreate_all
{
    resource_leave_all

    local host primary_host_to_join res
    for host in "${global_host_list[@]}"; do
        for res in "${resource_name_list[@]}"; do
            if [ -z "$primary_host_to_join" ]; then
                resource_create $host $res
                primary_host_to_join=$host
            else
                resource_join $host $res $primary_host_to_join
            fi
        done
    done
}

function resource_leave_all
{
    local host res
    for host in "${global_host_list[@]}"; do
        for res in "${resource_name_list[@]}"; do
            resource_leave $host $res
        done
        cluster_remove_debugfiles $host
    done
}

function resource_leave
{
    local host=$1 res=$2
    if resource_is_data_device_mounted $host $res; then
        local dev=$(resource_get_data_device $res)
        resource_clear_data_device $host $res
        mount_umount_data_device $host $res
    fi

    if resource_joined $host $res; then
        resource_secondary $host $res
        local cmd
        for cmd in "down" "leave-resource --force"; do
            marsadm_do_cmd $host "$cmd" $res || lib_exit 1
        done
        resource_do_after_leave_loops $host $res
    fi
    resource_mount_mars_and_rm_resource_dir_all $res
}

function resource_do_after_leave_loops
{
    local host=$1 res=$2
    local count=0 act_deleted_nr max_to_delete_nr
    lib_vmsg "  checking whether there is s.th. to delete on $host"
    max_to_delete_nr=$(marsadm_get_highest_to_delete_nr $host) || \
                                                            lib_exit 1
    lib_vmsg "  max_to_delete_nr on $host: $max_to_delete_nr"
    while true; do
        act_deleted_nr=$(marsadm_get_deleted_link_value $host)
        if [ $act_deleted_nr -lt $max_to_delete_nr ]; then
            let count+=1
            sleep 1
                lib_vmsg "  $count retries: max_to_delete=$max_to_delete_nr, act_deleted=$act_deleted_nr"

            if [ $count -eq $resource_maxloop_leave_resource ]; then
                lib_exit 1 "max number of loops exceeded"
            fi
            continue
        fi
        break
    done
    count=0
    while true; do
        local number_hidden_links
        lib_vmsg "  determininig numnber of hidden links on $host $res"
        number_hidden_links=$(marsadm_get_number_of_hidden_delete_symlinks $host $res) || lib_exit 1
        if [ $number_hidden_links -gt 0 ]; then
            let count+=1
            sleep 1
            lib_vmsg "  $count retries: number of hidden links = $number_hidden_links"
            if [ $count -gt $resource_maxloop_leave_resource ]; then
                lib_exit 1 "max number of loops exceeded"
            fi
            continue
        fi
        break
    done
    count=0
    while true; do
        local link="$(resource_get_resource_dir $res)/actual-$host/open-count"
        lib_linktree_check_link $host "$link" "0"
        link_status=$?
        if [ $link_status -ne ${global_link_status["link_ok"]} \
             -a $link_status -ne ${global_link_status["link_does_not_exist"]} ]
        then
            let count+=1
            sleep 1
            local str=$(lib_linktree_status_to_string $link_status)
            lib_vmsg "  $count retries: link $host:$link has yet state $str"
            if [ $count -gt $resource_maxloop_leave_resource ]; then
                lib_exit 1 "max number of loops exceeded"
            fi
            continue
        fi
        return 1
    done
}

function resource_secondary
{
    local host=$1 res="$2"
    marsadm_do_cmd $host "secondary" $res || lib_exit 1
    marsadm_do_cmd $host "wait-resource" "$res is-primary-off"
}

function resource_joined
{
    local host=$1 res="$2"
    local link="$(resource_get_resource_dir $res)/data-$host"
    local link_value_expected=(".")
    lib_linktree_check_link $host "$link" "$link_value_expected"
    link_status=$?
    if [ $link_status -eq ${global_link_status["link_ok"]} ]; then
        lib_vmsg "  resource $res on $host exists"
        return 0
    else
        lib_vmsg "  resource $res on $host does not exist"
        return 1
    fi
}


function resource_run_first
{
    resource_run ${resource_name_list[0]}
}

function resource_run_all
{
    local res
    for res in ${resource_name_list[@]}; do
        resource_run $res
    done
}

function resource_run
{
    local res=$1 host i
    for i in ${!global_host_list[*]}; do
        host=${global_host_list[$i]}
        if [ $i -eq 0 ]; then
            resource_create $host $res
        else
            resource_join $host $res ${global_host_list[0]}
        fi
    done
}

function resource_multi_res_run
{
    :
}

function resource_fill_mars_dir
{
    local primary_host=${global_host_list[0]}
    local secondary_host=${global_host_list[1]}
    local res=${resource_name_list[0]}
    local dev=$(lv_config_get_lv_device $res)
    local data_dev=$(resource_get_data_device $res)
    local data_dev_size=$(lv_config_get_lv_size_from_name $res)
    local mars_lv_name=${cluster_mars_dir_lv_name_list[$primary_host]}
    local mars_dev=$(lv_config_get_lv_device $mars_lv_name)
    local mars_dev_size=$(lv_config_get_lv_size_from_name $mars_lv_name)
    local time_waited writer_pid writer_script write_count control_nr

    if [ $resource_use_data_dev_writes_to_fill_mars_dir -eq 1 ]; then
        resource_dd_until_mars_dir_full $primary_host $res \
                                        $global_mars_directory \
                                        $data_dev $mars_dev_size \
                                        $data_dev_size "control_nr"
        resource_check_low_space_error $primary_host $res "sequence_hole"
    else
        lib_rw_start_writing_data_device $primary_host "writer_pid" \
                                         "writer_script" 0 2 $res ""
        resource_write_file_until_mars_dir_full $primary_host \
                                                $global_mars_directory \
                                                $mars_dev_size \
                                                $resource_big_file
    fi

    if [ $resource_use_data_dev_writes_to_fill_mars_dir -eq 0 ]; then
        lib_rw_stop_writing_data_device $primary_host $writer_script \
                                        "write_count"
        main_error_recovery_functions["lib_rw_stop_scripts"]=
        lib_vmsg "  removing $primary_host:$resource_big_file"
        lib_remote_idfile $primary_host "rm -f $resource_big_file" || lib_exit 1
    fi

    resource_check_proc_sys_mars_emergency_file $primary_host

    resource_resize_mars_dir $primary_host $mars_dev $(($mars_dev_size + 10))

    lib_rw_start_writing_data_device $primary_host "writer_pid" \
                                     "writer_script"  0 3 $res ""

    marsadm_do_cmd $secondary_host "invalidate" $res
    lib_wait_for_initial_end_of_sync $primary_host $secondary_host $res \
                                  $resource_maxtime_initial_sync \
                                  $resource_time_constant_initial_sync \
                                  "time_waited"

    lib_rw_stop_writing_data_device $primary_host $writer_script "write_count"
    main_error_recovery_functions["lib_rw_stop_scripts"]=

    marsview_wait_for_state $secondary_host $res "disk" "Uptodate" \
                            $resource_maxtime_state_constant || lib_exit 1

    lib_rw_compare_checksums $primary_host $secondary_host $res 0 "" ""
}

function resource_resize_mars_dir
{
    local host=$1 mars_dev=$2 new_size=$3
    lib_vmsg "  resizing $host:$mars_dev to $new_size GB"

    lv_config_resize_device $host $mars_dev $new_size
    lib_remote_idfile $host "resize2fs $mars_dev" || lib_exit 1
}

function resource_check_proc_sys_mars_emergency_file
{
    local host=$1 value
    lib_vmsg "  checking value in $host:$resource_proc_sys_mars_reset_emergency_file"
    value=$(lib_remote_idfile $host \
              "cat $resource_proc_sys_mars_reset_emergency_file")  || lib_exit 1
    if [ $value -ne 1 ];then
        lib_exit 1 "wrong value $value (!= 1) in $host:$resource_proc_sys_mars_reset_emergency_file"
    fi
}

function resource_write_file_until_mars_dir_full
{
    [ $# -eq 4 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local host=$1 mars_dir=$2 mars_dev_size=$3 file_to_fill=$4
    local df_out use_percent rc
    datadev_full_dd_on_device $host $file_to_fill \
                            $(( 1024 * ($mars_dev_size + 1) )) 4711 1
    lib_remote_idfile $host "ls -l $file_to_fill" || lib_exit 1
    lib_vmsg "  checking space on $host:$mars_dir"
    df_out=($(lib_remote_idfile $host "df -B1 $mars_dir")) || lib_exit 1
    use_percent=$(expr "${df_out[*]}" : '.* \([0-9][0-9]*\)%')
    rc=$?
    if [ $rc -ne 0 ]; then
        lib_exit 1 "cannot determine use% in df output ${df_out[*]}"
    fi
    if [ $use_percent -lt 99 ];then 
        lib_exit 1 "$host:$mars_dir used only at $use_percent"
    fi
}

function resource_check_low_space_error
{
    local host=$1 res=$2 err_type="$3" msgtype patternlist msgpattern
    local msgtype="err"
    msgfile=$(resource_get_resource_dir $res)/${resource_msgfile_list["$msgtype"]}
    eval msgpattern='"${resource_mars_dir_full_'$msgtype'_pattern_list[$err_type]}"'
    if [ -z "$msgpattern" ]; then
        lib_exit 1 "pattern resource_mars_dir_full_${msgtype}_pattern_list[$err_type] not found"
    fi
    msgpattern="${msgpattern//$resource_msg_resource_dir_name_pattern/$(resource_get_resource_dir $res)}"
    lib_err_wait_for_error_messages $host $msgfile "$msgpattern" 1 10 "ge"
}

function resource_dd_until_mars_dir_full
{
    [ $# -eq 7 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local primary_host=$1 res=$2 mars_dir=$3 data_dev=$4 mars_dev_size=$5
    local data_dev_size=$6 varname_control_nr=$7
    local written=0 control_nr=1000
    local warning_threshold=$((2 * 1<<30))
    local write_per_loop=1 # G
    local jammed_warning_found=0

    while true;do
        local free df_out
        datadev_full_dd_on_device $primary_host $data_dev \
                                  $(( 1024 * $write_per_loop )) $control_nr 0
        let written+=$write_per_loop
        let control_nr+=1
        df_out=($(lib_remote_idfile $primary_host "df -B1 $mars_dir | \
                                                   tail -1")) || lib_exit 1
        free=${df_out[2]}
        if ! expr "$free" : '^[0-9][0-9]*$' >/dev/null; then
            lib_exit 1 "cannot determine free space from ${df_out[@]} (free=$free)"
        fi
        lib_vmsg "  free on $primary_host:$mars_dir: $free"
        if [ $free -le $warning_threshold -a $jammed_warning_found -eq 0 ]; then
            resource_check_low_space_error $primary_host $res "jammed"
            jammed_warning_found=1
        fi
        if [ $written -ge $(($mars_dev_size + 1)) ]; then
            break
        fi
    done
    eval $varname_control_nr=$(($control_nr - 1))
}

function resource_up
{
    local host=$1 res=$2 rc
    marsadm_do_cmd $host "up" $res
    rc=$?
    return $rc
}

function resource_mount_mars_and_rm_resource_dir_all
{
    local res=$1 host
    local res_dir=$(resource_get_resource_dir $res)

    cluster_rmmod_mars_all

    for host in "${global_host_list[@]}"; do
        local mars_lv=${cluster_mars_dir_lv_name_list[$host]}
        local mars_dev=$(lv_config_get_lv_device $mars_lv)
        lib_vmsg "  removing $host:$res_dir whether mounted or not"
        lib_remote_idfile $host "rm -rf $res_dir" || lib_exit 1
        lib_vmsg "  check whether mars device $host:$mars_dev exists"
        if lib_remote_idfile $host "ls -l $mars_dev"; then
            cluster_mount_mars_dir $host
            lib_vmsg "  removing $host:$res_dir"
            lib_remote_idfile $host "rm -rf $res_dir" || lib_exit 1
        fi
    done
}

function resource_create
{
    local host=$1 res=$2

    local dev="$(lv_config_get_lv_device $res)"
    local size="$(lv_config_get_lv_size_from_name $res)"
    if [ $resource_fs_on_data_device_necessary -eq 1 ]; then
        lib_rw_remote_check_device_fs $host $dev ${resource_fs_type_list[$res]}
    fi
    if ! resource_up $host $res; then
        local count=0 rc 
        while true; do
            cluster_insert_mars_module_all
            marsadm_do_cmd $host "create-resource $resource_create_flag" \
                                 "$res $dev $res ${size}G"
            marsadm_do_cmd $host "wait-resource" "$res is-device-on"
            rc=$?
            if [ $rc -ne 0 ]; then
                let count+=1
                lib_vmsg "  $count retry failed"
                if [ $count -ge $resource_number_of_create_retries ]; then
                    lib_exit 1 "max. number of retries $resource_number_of_create_retries exceeded"
                else
                    sleep 4
                    continue
                fi
            else
                break
            fi
        done
        resource_check_data_link $host $res $dev
        local role
        role=($marsadm_get_role $host $res) || lib_exit 1
        if [ "$role" = "secondary" ]; then
            marsadm_do_cmd $host "primary" $res
        fi
    fi
    resource_check_links_after_create $host $res
    resource_check_data_device_after_create $host $res
    if [ $resource_fs_on_data_device_necessary -eq 1 ]; then
        resource_check_mount_and_rmmod_possibilities $host $res
    fi
    resource_underlying_device_is_not_mountable $host $dev $res || lib_exit 1
    cluster_create_debugfiles $host
}

function resource_check_data_link
{
    local host=$1 res=$2 dev=$3
    local link=$(lib_linktree_get_res_host_linkname $host $res "data")
    lib_linktree_check_link $host "$link" $dev
}

function resource_get_data_device
{
    local res=$1
    echo /dev/mars/$res 
}

function resource_is_data_device_mounted
{
    local host=$1 res=$2 rc
    local dev=$(resource_get_data_device $res)
    local mount_point
    mount_is_device_mounted $host $dev "mount_point"
}

function resource_check_data_device_after_create
{
    local host=$1 res=$2
    local dev=$(resource_get_data_device $res)
    local waited=0 rc
    while true; do
        lib_vmsg "  checking existence of device $dev on $host"
        lib_remote_idfile $host "ls -l --full-time $dev"
        rc=$?
        if [ $rc -eq 0 ]; then
            break
        fi
        sleep 1
        let waited+=1
        lib_vmsg "  waited $waited for ls $dev on $host to succeed"
        if [ $waited -ge $resource_maxtime_to_wait_for_ls ]; then
            lib_exit 1 "maxtime $resource_maxtime_to_wait_for_ls exceeded"
        fi
    done
}

function resource_check_mount_and_rmmod_possibilities
{
    local host=$1 res=$2
    local data_dev=$(resource_get_data_device $res)
    local mount_point
    resource_check_mount_point_directories $host
    if ! mount_is_device_mounted $host $data_dev "mount_point"
    then
        mount_mount $host $data_dev $(resource_get_mountpoint $res) \
                                    ${resource_fs_type_list[$res]} || lib_exit 1
    fi
    resource_check_whether_rmmod_mars_fails $host $data_dev
    mount_umount $host $data_dev $(resource_get_mountpoint $res) || lib_exit 1
}

function resource_check_whether_rmmod_mars_fails
{
    local host=$1 dev=$2 rc
    lib_vmsg "  checking whether rmmod mars fails on $host"
    lib_remote_idfile $host "rmmod mars"
    rc=$?
    if [ $rc -eq 0 ]; then
        local dev=
        lib_exit 1 "rmmod mars could be removed while $dev is mounted"
    fi
}

function resource_check_mount_point_directories
{
    local host=$1 res
    for res in ${resource_name_list[@]}; do
        local dir=$(resource_get_mountpoint $res)
        lib_vmsg "  checking mount point $dir on $host"
        lib_remote_idfile $host "if [ ! -d $dir ]; then mkdir $dir; fi" \
                                                                || lib_exit 1
    done
}

function resource_write_and_check
{
    local primary_host=${global_host_list[0]}
    eval local secondary_hosts=('"${global_host_list["{1..'${#global_host_list[*]}'}"]}"')
    local host
    local res=${resource_name_list[0]}
    local writer_pid writer_script write_count
    local dev=$(lv_config_get_lv_device $res)
    local time_waited

    resource_prepare
    resource_run_all
    for host in ${secondary_hosts[@]}; do
        lib_wait_for_initial_end_of_sync $primary_host $host $res \
                                         $resource_maxtime_initial_sync \
                                         $resource_time_constant_initial_sync \
                                         "time_waited"
    done
    mount_mount_data_device $primary_host $res
    resource_clear_data_device $primary_host $res

    lib_rw_start_writing_data_device $primary_host "writer_pid" \
                                     "writer_script" 0 1 $res ""
    sleep 15
    lib_rw_stop_writing_data_device $primary_host $writer_script "write_count"
    main_error_recovery_functions["lib_rw_stop_scripts"]=
    sleep 5
    mount_umount_data_device $primary_host $res
    for host in ${secondary_hosts[@]}; do
        lib_wait_for_secondary_to_become_uptodate_and_cmp_cksums "resource" \
                                                $host $primary_host \
                                                $res $dev 0
    done
}

function resource_underlying_device_is_not_mountable
{
    local host=$1 dev=$2 res=$3 rc
    resource_check_mount_point_directories $host
    lib_vmsg "  checking whether mounting $dev on $(resource_get_mountpoint $res) on $host fails"
    mount_mount $host $dev $(resource_get_mountpoint $res) \
                           ${resource_fs_type_list[$res]}
    rc=$?
    if [ $rc -eq 0 ]; then
        return 1
    fi
    return 0
}

function resource_join
{
    local host=$1 res=$2 primary_host=$3

    local dev="$(lv_config_get_lv_device $res)"
    local count=0 rc
    while true; do
        if ! resource_up $host $res; then
            marsadm_do_cmd $host "join-resource" "$res $dev"
        fi
        marsadm_do_cmd $host "wait-resource" "$res is-device-off"
        rc=$?
        if [ $rc -ne 0 ]; then
            sleep 1
            let count+=1
            lib_vmsg "  $count tries to join resource $res on $host"
            if [ $count -ge $resource_number_of_mount_join_resource_cycles ]
            then
                lib_exit 1 "maxtime $resource_number_of_mount_join_resource_cycles exceeded"
            fi
            continue
        fi
        break
    done
    resource_check_data_link $host $res $dev
    resource_check_links_after_join $host $res $primary_host

    resource_underlying_device_is_not_mountable $host $dev $res || lib_exit 1
}

function resource_check_links_after_join
{
    local host=$1 res=$2 primary_host=$3 

    local reslink_name link_value_expected link_status

    local link="$(lib_linktree_get_designated_primary_linkname $res)"
    local link_value_expected="$primary_host"
    lib_linktree_check_link $host "$link" "$link_value_expected"
    link_status=$?
    if [ $link_status -ne ${global_link_status["link_ok"]} ]; then
        lib_exit 1 "resource $res on $host has not been joined"
    fi
}

function resource_check_links_after_create
{
    local host=$1 res=$2 reslink_name link_value_expected link_status

    local link="$(lib_linktree_get_designated_primary_linkname $res)"
    local link_value_expected="$host"
    lib_linktree_check_link $host "$link" "$link_value_expected"
    link_status=$?
    if [ $link_status -ne ${global_link_status["link_ok"]} ]; then
        lib_exit 1 "resource $res on $host has not been created"
    fi
}

function resource_clear_data_device
{
    local host=$1 res=$2
    local mount_point=$(resource_get_mountpoint $res)
    local str="test"
    if [ -z "$mount_point" ]; then
        lib_exit 1 "cannot determine mount_point for resource $res"
    fi
    if ! expr "$mount_point" : ".*$str.*" >/dev/null; then
        lib_exit 1 "mount_point $mount_point does not contain string $str"
    fi
    lib_vmsg "  clearing $host:$mount_point"
    lib_remote_idfile $host "if cd $mount_point; then shopt -s dotglob && rm -rf *;fi"
}

function resource_kill_all_scripts
{
    local host
    for host in "${global_host_list[@]}"; do
        lib_vmsg "  killing all $global_prefix_scripts scripts on $host"
        lib_remote_idfile $host 'for p in $(pgrep -f '"$global_prefix_scripts"'); do if [ $p -ne $$ ] && ps -p $p >/dev/null; then echo killing:; ps -fp $p; kill -9 $p; fi; done'
    done
}

function resource_check_replication
{
    [ $# -eq 4 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local primary_host=$1 secondary_host=$2 res=$3 debug_msg_prefix="$4"
    local data_dev=$(resource_get_data_device $res)
    lib_vmsg  " ${debug_msg_prefix}check replication, primary=$primary_host, secondary=$secondary_host"
    marsadm_do_cmd $primary_host "wait-resource" "$res is-device-on" || \
                                                                    lib_exit 1
    lib_vmsg "  ${debug_msg_prefix}write to $primary_host:$data_dev and log-rotate/delete"
    local count=0 maxcount=3
    while true; do
        lib_remote_idfile $primary_host \
                          "yes | dd oflag=direct bs=4096 count=1 of=$data_dev" \
                                                            || lib_exit 1
        if [ $switch2primary_logrotate_new_primary -eq 0 ]; then
            break
        fi
        marsadm_do_cmd $primary_host "log-rotate" $res || lib_exit 1
        if [ $(($count % 2 )) -eq 0 ]; then
            marsadm_do_cmd $primary_host "log-delete" $res || lib_exit 1
        fi
        let count+=1
        if [ $count -eq $maxcount ]; then
            break
        fi
    done
    lib_vmsg  " ${debug_msg_prefix}wait for secondary $secondary to become uptodate and calculate checksums"
    lib_wait_for_secondary_to_become_uptodate_and_cmp_cksums "resource" \
                                            $secondary_host $primary_host \
                                            $res $data_dev 0
}

function resource_leave_while_sync
{
    local primary_host=${global_host_list[0]}
    local secondary_host=${global_host_list[1]}
    local res=${resource_name_list[0]}
    local dev="$(lv_config_get_lv_device $res)"
    local time_waited

    lib_wait_for_initial_end_of_sync $primary_host $secondary_host $res \
                                  $resource_maxtime_initial_sync \
                                  $switch2primary_time_constant_initial_sync \
                                  "time_waited"
    lib_vmsg "  ${FUNCNAME[0]}: sync time: $time_waited"

    # prevent too fast sync 
    perftest_sysctrl_sync_modus "no_fast_sync" $secondary_host
    marsadm_do_cmd $secondary_host "invalidate" $res || lib_exit 1
    sleep 2

    resource_check_sync $secondary_host $primary_host $res "running"

    if [ $resource_cut_network_connection_while_sync -eq 1 ]; then
        net_do_impact_cmd $secondary_host "on" "remote_host=$primary_host"
    fi
    perftest_sysctrl_sync_modus "fast_sync" $secondary_host

    marsadm_do_cmd $secondary_host "down" $res || lib_exit 1
    marsadm_do_cmd $secondary_host "leave-resource" $res || lib_exit 1

    if [ $resource_cut_network_connection_while_sync -eq 1 ]; then
        net_do_impact_cmd $secondary_host "off" "remote_host=$primary_host"
    fi
    marsadm_do_cmd $secondary_host "join-resource" "$res $dev" || lib_exit 1

    lib_wait_for_initial_end_of_sync $primary_host $secondary_host $res \
                                     $resource_maxtime_initial_sync \
                                     $resource_time_constant_initial_sync \
                                     "time_waited"
    resource_check_replication $primary_host $secondary_host $res ""
}

function resource_check_sync
{
    [ $# -eq 4 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local secondary_host=$1 primary_host=$2 res=$3 mode_req="$4"
    lib_vmsg "  check whether sync has mode $mode_req on $secondary_host"
    case "$mode_req" in # ((
        running) 
            local i host link_primary link_secondary
            local link_val_primary link_val_secondary
            for i in "primary" "secondary"; do
                eval host='$'$i'_host'
                eval link_$i="$(lib_linktree_get_res_host_linkname $host $res \
                                                                 syncstatus)"
                eval link_val_$i='$(lib_remote_idfile $host "readlink $link'_$i'")' || lib_exit 1
            done
            if [ "$link_val_primary" = "$link_val_secondary" ]; then
                lib_exit 1 "no sync running. Links $link_primary and $link_secondary has same value $link_val_primary"
            fi
            ;;
        *) lib_exit 1 "wrong mode $mode_req"
        ;;
    esac
}

function resource_recreate_standalone
{
    local primary_host=${global_host_list[0]}
    local secondary_host=${global_host_list[1]}
    local res=${resource_name_list[0]}
    local dev="$(lv_config_get_lv_device $res)"
    local time_waited

    lib_wait_for_initial_end_of_sync $primary_host $secondary_host $res \
                                  $resource_maxtime_initial_sync \
                                  $switch2primary_time_constant_initial_sync \
                                  "time_waited"
    lib_vmsg "  ${FUNCNAME[0]}: sync time: $time_waited"

    net_do_impact_cmd $primary_host "on" "remote_host=$secondary_host"
    marsadm_do_cmd $primary_host "secondary" "$res" || lib_exit 1
    marsadm_do_cmd $primary_host "down" "$res" || lib_exit 1
    marsadm_do_cmd $primary_host "leave-resource" "$res" || lib_exit 1
    marsadm_do_cmd $primary_host "create-resource --force" "$res $dev" || \
                                                                    lib_exit 1
    switch2primary_check_standalone_primary $primary_host $res
    net_do_impact_cmd $primary_host "off" "remote_host=$secondary_host"
    marsadm_do_cmd $secondary_host "down" "$res" || lib_exit 1
    marsadm_do_cmd $secondary_host "leave-resource" "$res" || lib_exit 1
    marsadm_do_cmd $secondary_host "join-resource" "$res $dev" || lib_exit 1
    lib_wait_for_initial_end_of_sync $primary_host $secondary_host $res \
                                  $resource_maxtime_initial_sync \
                                  $switch2primary_time_constant_initial_sync \
                                  "time_waited"
    lib_vmsg "  ${FUNCNAME[0]}: sync time: $time_waited"
    lib_rw_compare_checksums $primary_host $secondary_host $res 0 "" ""
}

function resource_per_resource_emergency
{
    local primary_host=${global_host_list[0]}
    local secondary_host=${global_host_list[1]}
    local mars_dev_size_available_mb
    local dev=$(lv_config_get_lv_device $res)
    local data_dev=$(resource_get_data_device $res)
    local data_dev_size=$(lv_config_get_lv_size_from_name $res)
    local time_waited writer_pid writer_script write_count control_nr
    declare -A writer_script_per_resource

    mars_dev_size_available_mb=$(datadev_full_get_available_free_space_mb \
                                 $primary_host) || lib_exit 1

    for res in ${resource_name_list[@]}; do
        mount_mount_data_device $primary_host $res
        resource_reset_emergency_limit $primary_host $res
        lib_rw_start_writing_data_device $primary_host "writer_pid" \
                                         "writer_script" 0 4 $res $res
        writer_script_per_resource[$res]=$writer_script
    done

    if [ $resource_put_only_one_to_emergency -eq 1 ]; then
        local i
        res=${resource_name_list[0]}
        resource_test_emergency_on_one_resource $primary_host $secondary_host \
                                            $mars_dev_size_available_mb $res \
                                            ${writer_script_per_resource[$res]}
        # check the other resources
        for i in $(seq 1 1 $(( ${#resource_name_list[*]} - 1 ))); do
            res=${resource_name_list[$i]}
            lib_rw_stop_writing_data_device $primary_host \
                                        ${writer_script_per_resource[$res]} \
                                        "write_count"
            resource_check_resource_running $primary_host $secondary_host $res
        done
    else
        resource_test_emergency_on_all_resources $primary_host $secondary_host \
                                                 $mars_dev_size_available_mb
    fi
    main_error_recovery_functions["lib_rw_stop_scripts"]=
    for res in ${resource_name_list[@]}; do
        resource_reset_emergency_limit $primary_host $res
    done

}

function resource_reset_emergency_limit
{
    local host=$1 res=$2
    marsadm_do_cmd $host "emergency-limit" "$res 0" || lib_exit 1
}

function resource_set_emergency_limit
{
    local host=$1 res=$2 percentage=$3
    marsadm_do_cmd $host "emergency-limit" "$res $((100 - $percentage))" || \
                                                                    lib_exit 1
}

# when entering this function it's assumed that on all resources write processes
# are running.
function resource_test_emergency_on_all_resources
{
    [ $# -eq 3 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local primary_host=$1 secondary_host=$2 mars_dev_size_available_mb=$3
    local res list_cmd res_list sort_opt=""

    for res in ${resource_name_list[@]}; do
        local p=${resource_emergency_percentage[$res]}
        if [ -z "$p" ]; then
            lib_exit 1 "  missing value in resource_emergency_percentage for resource $res"
        fi
        resource_set_emergency_limit $primary_host $res $p
    done

    # the resources must be listed in ascending order of emergency 
    # percentages, because we create additional files to put the resources
    # in emergency mode
    list_cmd='for r in ${resource_name_list[@]}; do echo "$r ${resource_emergency_percentage[$r]}"; done | sort -k2,2n$sort_opt | sed "s/ .*//"'
    eval res_list='($('$list_cmd'))'
    local percent_used=0
    for res in ${res_list[@]}; do
        local p=${resource_emergency_percentage[$res]}
        # we use aditional 10 percent because the removal of the file later
        # should free enough space to be able to leave emergency mode
        local percent_to_write=$(( $p - $percent_used + 10 ))
        local to_write_mb=$(( ($mars_dev_size_available_mb \
                               * $percent_to_write) / 100 ))
        resource_put_resource_to_emergency_mode $primary_host $res \
                                        ${resource_emergency_percentage[$res]} \
                                        $resource_big_file.$res $to_write_mb
        let percent_used+=$percent_to_write
    done

    # the resources must be returned to normal operation in descending order of 
    # emergency percentages (by freeing diskspace accordingly), because
    # we remove the additional files created above in reverse order
    sort_opt="r"
    eval res_list='($('$list_cmd'))'
    for res in ${res_list[@]}; do
        lib_vmsg "  removing $primary_host:$resource_big_file.$res"
        lib_remote_idfile $primary_host "rm -f $resource_big_file.$res" || \
                                                                    lib_exit 1

        lib_rw_stop_writing_data_device $primary_host $writer_script "write_count"

        resource_correct_emergency $primary_host $secondary_host $res
    done

}

# when entering this function it's assumed that a process is actually writing
# on the resource on the primary host
function resource_test_emergency_on_one_resource
{
    [ $# -eq 5 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local primary_host=$1 secondary_host=$2 mars_dev_size_available_mb=$3
    local res=$4 writer_script=$5
    local emergency_percentage=${resource_emergency_percentage[$res]}
    local fill_size_mb=$(( ($mars_dev_size_available_mb \
                            * $emergency_percentage) / 100 ))
    local time_waited host write_count writer_pid
    
    if [ -z "$emergency_percentage" ]; then
        lib_exit 1 "  missing value in resource_emergency_percentage for resource $res"
    fi

    resource_put_resource_to_emergency_mode $primary_host $res \
                                            $emergency_percentage \
                                            $resource_big_file $fill_size_mb

    lib_vmsg "  removing $primary_host:$resource_big_file"
    lib_remote_idfile $primary_host "rm -f $resource_big_file" || lib_exit 1

    lib_rw_stop_writing_data_device $primary_host $writer_script "write_count"

    resource_correct_emergency $primary_host $secondary_host $res

}

function resource_check_logfile_change
{
    local host=$1 primary_host=$2 res=$3
    local last_logfile last_logfile_old length length_old
    local waited=0 maxwait=30

    lib_vmsg "  checking whether logfiles are written on $res on $host"
    last_logfile_old=$(marsadm_get_last_logfile $host $res $primary_host) || \
                                                                    lib_exit 1
    length_old=$(file_handling_get_file_length \
                                       $host $last_logfile_old) || lib_exit 1
    lib_vmsg "  start: last logfile:length on $host: $last_logfile_old:$length_old"
    while true; do
        last_logfile=$(marsadm_get_last_logfile $host $res $primary_host) || \
                                                                    lib_exit 1
        length=$(file_handling_get_file_length $host $last_logfile) || \
                                                                    lib_exit 1
        lib_vmsg "  act.: last logfile:length on $host: $last_logfile:$length"
        if [ "$last_logfile" != "$last_logfile_old" -o $length -ne $length_old ]
        then
            break
        fi
        sleep 1
        let waited+=1
        lib_vmsg "  waited $waited for logfiles to change for $res on $host"
        if [ $waited -eq $maxwait ]; then
            lib_exit 1 "maxwait $maxwait exceeded"
        fi
    done
}

function resource_put_resource_to_emergency_mode
{
    [ $# -eq 5 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local host=$1 res=$2 emergency_percentage=$3 big_file=$4 big_file_size_mb=$5
    local fill_size_mb marsadm_out

    resource_set_emergency_limit $primary_host $res $emergency_percentage

    lib_vmsg "  creating $big_file with $big_file_size_mb MB to put $res in emerg. mode on $host"

    datadev_full_dd_on_device $host $big_file $big_file_size_mb 4811 0

    resource_check_low_space_error $host $res "sequence_hole"

    marsadm_out=$(marsadm_do_pur_cmd $host "view-is-emergency" "$res") || \
                                                                    lib_exit 1
    if [ "$marsadm_out" != "1" ]; then
        lib_vmsg "  invalid output of marsadm view-is-emergency $res: $marsadm_out" >&2
        lib_vmsg "  df -h $global_mars_directory on $host:" >&2
        lib_remote_idfile $host "df -h $global_mars_directory" >&2
        lib_exit 1 
    fi

    resource_check_proc_sys_mars_emergency_file $host

}

function resource_check_resource_running
{
    local primary_host=$1 secondary_host=$2 res=$3
    local dev=$(lv_config_get_lv_device $res)
    local writer_script writer_pid write_count

    marsview_wait_for_state $secondary_host $res "disk" "Uptodate" 3 || \
                                                                    lib_exit 1

    lib_rw_start_writing_data_device $primary_host "writer_pid" \
                                     "writer_script" 0 4 $res $res

    for host in $primary_host $secondary_host; do
        resource_check_logfile_change $host $primary_host $res
    done

    lib_rw_stop_writing_data_device $primary_host $writer_script "write_count"

    mount_umount_data_device $primary_host $res

    lib_wait_for_secondary_to_become_uptodate_and_cmp_cksums "resource" \
                                            $secondary_host $primary_host \
                                            $res $dev 0
}

function resource_correct_emergency
{
    local primary_host=$1 secondary_host=$2 res=$3

    marsadm_do_cmd $secondary_host "invalidate" $res

    lib_wait_for_initial_end_of_sync $primary_host $secondary_host $res \
                                  $resource_maxtime_initial_sync \
                                  $resource_time_constant_initial_sync \
                                  "time_waited"

    resource_check_resource_running $primary_host $secondary_host $res
}

function resource_get_mountpoint
{
    local res=$1 # has the form lv-3-1
    local res_nr=${res#*-}
    res_nr=${res_nr%%-*}
    if ! expr "$res_nr" : '\([0-9][0-9]*\)$' >/dev/null; then
        lib_exit 1 "invalid resource name $res"
    fi
    echo ${resource_mount_point_prefix}$res_nr
}

function resource_get_resource_dir
{
    local res=$1
    echo ${resource_dir_prefix}$res
}
