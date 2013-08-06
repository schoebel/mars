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

function resource_prepare
{
    resource_check_variables
    cluster_rmmod_mars_all
    cluster_mount_mars_dir_all
    cluster_insert_mars_module_all
    resource_leave_all
    cluster_insert_mars_module_all
}

function resource_check_variables
{
    if ! expr "${lv_config_name_list[*]}" : "${resource_name_list[*]}" \
                                                                    >/dev/null
    then
        lib_exit 1 "resource_name_list = '${resource_name_list[*]}' is no substring of '${lv_config_name_list[*]}' = lv_config_name_list"
    fi
}

function resource_recreate_all
{
    resource_leave_all

    local host primary_host_to_join res
    for host in "${main_host_list[@]}"; do
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
    for host in "${main_host_list[@]}"; do
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
        local dev=$(resource_get_name_data_device $res)
        mount_umount $host $dev ${resource_mount_point_list[$res]} || lib_exit 1
    fi

    if resource_joined $host $res; then
        resource_secondary $host $res
        local cmd
        for cmd in "down" "--force leave-resource"; do
            marsadm_do_cmd $host "$cmd" $res || lib_exit 1
        done
        resource_do_after_leave_loops $host $res
    fi
    resource_rm_resource_dir $res
}

function resource_do_after_leave_loops
{
    local host=$1 res=$2
    local count=0 act_deleted_nr max_to_delete_nr
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
        local link="${resource_dir_list[$res]}/actual-$host/open-count"
        lib_linktree_check_link $host "$link" "0"
        link_status=$?
        if [ $link_status -ne ${main_link_status["link_ok"]} \
             -a $link_status -ne ${main_link_status["link_does_not_exist"]} ]
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
    local link="${resource_dir_list[$res]}/data-$host"
    local link_value_expected=(".")
    lib_linktree_check_link $host "$link" "$link_value_expected"
    link_status=$?
    if [ $link_status -eq ${main_link_status["link_ok"]} ]; then
        lib_vmsg "  resource $res on $host exists"
        return 0
    else
        lib_vmsg "  resource $res on $host does not exist"
        return 1
    fi
}


function resource_run
{
    resource_create ${main_host_list[0]} ${resource_name_list[0]}
    if [ ${#main_host_list[@]} -gt 1 ]; then
        resource_join ${main_host_list[1]} \
                      ${resource_name_list[0]} \
                      ${main_host_list[0]}
    fi
}

function resource_multi_res_run
{
    :
}

function resource_fill_data_device
{
    local primary_host=${main_host_list[0]}
    local secondary_host=${main_host_list[1]}
    local res=${resource_name_list[0]}
    local dev=$(lv_config_get_lv_device $res)
    local data_dev=$(resource_get_name_data_device $res)
    local data_dev_size=$(lv_config_get_lv_size $res)
    local mars_lv_name=${cluster_mars_dir_lv_name_list[$primary_host]}
    local mars_dev=$(lv_config_get_lv_device $mars_lv_name)
    local mars_dev_size=$(lv_config_get_lv_size $mars_lv_name)
    local time_waited writer_pid writer_script write_count control_nr
    local primary_cksum secondary_cksum

    if [ $resource_use_data_dev_writes_to_fill_mars_dir -eq 1 ]; then
        resource_dd_until_mars_dir_full $primary_host $main_mars_directory \
                                        $data_dev $mars_dev_size \
                                        $data_dev_size "control_nr"
        resource_check_emergency_mode $primary_host $res
    else
        lib_rw_start_writing_data_device "writer_pid" "writer_script" \
                                          0 2 $res
        resource_write_file_until_mars_dir_full $primary_host \
                                                $main_mars_directory \
                                                $mars_dev_size \
                                                $resource_big_file
    fi

    if [ $resource_use_data_dev_writes_to_fill_mars_dir -eq 0 ]; then
        lib_rw_stop_writing_data_device $writer_script "write_count"
        lib_vmsg "  removing $primary_host:$resource_big_file"
        lib_remote_idfile $primary_host "rm -f $resource_big_file" || lib_exit 1
    fi

    resource_recreate_all
    lib_wait_for_initial_end_of_sync $secondary_host $res \
                                  $resource_maxtime_initial_sync \
                                  $resource_time_constant_initial_sync \
                                  "time_waited"
    lib_rw_compare_checksums $primary_host $secondary_host $dev 0 \
                             "primary_cksum" "secondary_cksum"
    if [ $resource_use_data_dev_writes_to_fill_mars_dir -eq 1 ]; then
        resource_check_data_on_data_device $primary_host $data_dev $control_nr \
                                           $data_dev_size $resource_big_file \
                                           "$primary_cksum"
        lib_remote_idfile $primary_host "rm -f $resource_big_file" || lib_exit 1
    fi
}

# compare actual data on data device with data written in
# resource_dd_until_mars_dir_full
function resource_check_data_on_data_device
{
    [ $# -eq 6 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local host=$1 data_dev=$2 control_nr=$3 data_dev_size=$4 dummy_file=$5
    local data_dev_cksum=($6) cksum_out

    lib_vmsg "  writing dummy file $host:$dummy_file with control_nr=$control_nr"
    datadev_full_dd_on_device $host $dummy_file $data_dev_size $control_nr 0 
    lib_remote_idfile $host "ls -l $dummy_file"
    lib_rw_cksum $host $dummy_file "cksum_out"
    if [ "${data_dev_cksum[*]}" != "${cksum_out[*]}" ]; then
        lib_exit 1 "cksum data dev: '${data_dev_cksum[*]}' != '${cksum_out[*]}' = cksum $dummy_file"
    fi

}

function resource_write_file_until_mars_dir_full
{
    [ $# -eq 4 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local host=$1 mars_dir=$2 mars_dev_size=$3 file_to_fill=$4
    local df_out use_percent rc
    datadev_full_dd_on_device $host $file_to_fill $(($mars_dev_size + 1)) 4711 1
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

function resource_check_emergency_mode
{
    local host=$1 res=$2 msgtype patternlist msgpattern
    for msgtype in err warn; do
        msgfile=${resource_dir_list[$res]}/${resource_msgfile_list[$msgtype]}
        eval patternlist='("${resource_mars_dir_full_'$msgtype'_pattern_list[@]}")'
        for msgpattern in "${patternlist[@]}"; do
            lib_err_wait_for_error_messages $host $msgfile \
                                        "$msgpattern" 1 1
        done
    done
}

function resource_dd_until_mars_dir_full
{
    [ $# -eq 6 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local primary_host=$1 mars_dir=$2 data_dev=$3 mars_dev_size=$4
    local data_dev_size=$5 varname_control_nr=$6
    local written=0 count=1000

    while true;do
        datadev_full_dd_on_device $primary_host $data_dev $data_dev_size \
                                  $count 0
        let written+=$data_dev_size
        let count+=1
        lib_remote_idfile $primary_host "df -B1 $mars_dir" || lib_exit 1
        if [ $written -ge $(($mars_dev_size + 1)) ]; then
            break
        fi
    done
    eval $varname_control_nr=$(($count - 1))
}

function resource_up
{
    local host=$1 res=$2 rc
    marsadm_do_cmd $host "up" $res
    rc=$?
    return $rc
}

function resource_rm_resource_dir
{
    local res=$1 host
    local res_dir=${resource_dir_list[$res]}

    cluster_rmmod_mars_all

    for host in "${main_host_list[@]}"; do
        lib_vmsg "  removing $host:$res_dir/*"
        lib_remote_idfile $host "rm -rf $res_dir/*" || lib_exit 1
    done
}

function resource_create
{
    local host=$1 res=$2

    local dev="$(lv_config_get_lv_device $res)"
    if [ $resource_recreate_fs_on_data_device_required -eq 1 ]; then
        lib_remote_check_device_fs $host $dev ${resource_fs_type_list[$res]}
    fi
    if ! resource_up $host $res; then
        local count=0 rc 
        while true; do
            cluster_insert_mars_module_all
            marsadm_do_cmd $host "create-resource $resource_create_flag" \
                                 "$res $dev"
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
    if [ $resource_recreate_fs_on_data_device_required -eq 1 ]; then
        resource_check_mount_and_rmmod_possibilities $host $res
    fi
    resource_underlying_device_is_not_mountable $host $dev || lib_exit 1
    cluster_create_debugfiles $host
}

function resource_check_data_link
{
    local host=$1 res=$2 dev=$3
    local link=$(lib_linktree_get_res_host_linkname $host $res "data")
    lib_linktree_check_link $host "$link" $dev
}

function resource_get_name_data_device
{
    local res=$1
    echo /dev/mars/$res 
}

function resource_is_data_device_mounted
{
    local host=$1 res=$2 rc
    local dev=$(resource_get_name_data_device $res)
    mount_is_device_mounted $host $dev
}

function resource_check_data_device_after_create
{
    local host=$1 res=$2
    local dev=$(resource_get_name_data_device $res)
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
    local data_dev=$(resource_get_name_data_device $res)
    resource_check_mount_point_directories $host
    if ! mount_is_device_mounted $host $data_dev ${resource_mount_point_list[$res]}
    then
        mount_mount $host $data_dev ${resource_mount_point_list[$res]} \
                                    ${resource_fs_type_list[$res]}
    fi
    resource_check_whether_rmmod_mars_fails $host $data_dev
    mount_umount $host $data_dev ${resource_mount_point_list[$res]} || \
                                                                    lib_exit 1
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
    local host=$1 dir
    for dir in ${resource_mount_point_list[@]}; do
        lib_vmsg "  checking mount point $dir on $host"
        lib_remote_idfile $host "if [ ! -d $dir ]; then mkdir $dir; fi" \
                                                                || lib_exit 1
    done
}

function resource_underlying_device_is_not_mountable
{
    local host=$1 dev=$2 rc
    local res=${resource_name_list[0]}
    resource_check_mount_point_directories $host
    lib_vmsg "  checking whether mounting $dev on ${resource_mount_point_list[$res]} on $host fails"
    mount_mount $host $dev ${resource_mount_point_list[$res]} \
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
    if [ $resource_recreate_fs_on_data_device_required -eq 1 ]; then
        lib_remote_check_device_fs $host $dev ${resource_fs_type_list[$res]}
    fi
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

    resource_underlying_device_is_not_mountable $host $dev || lib_exit 1
}

function resource_check_links_after_join
{
    local host=$1 res=$2 primary_host=$3 

    local reslink_name link_value_expected link_status

    local link="$(lib_linktree_get_primary_linkname $res)"
    local link_value_expected="$primary_host"
    lib_linktree_check_link $host "$link" "$link_value_expected"
    link_status=$?
    if [ $link_status -ne ${main_link_status["link_ok"]} ]; then
        lib_exit 1 "resource $res on $host has not been joined"
    fi
}

function resource_check_links_after_create
{
    local host=$1 res=$2 reslink_name link_value_expected link_status

    local link="$(lib_linktree_get_primary_linkname $res)"
    local link_value_expected="$host"
    lib_linktree_check_link $host "$link" "$link_value_expected"
    link_status=$?
    if [ $link_status -ne ${main_link_status["link_ok"]} ]; then
        lib_exit 1 "resource $res on $host has not been created"
    fi
}

