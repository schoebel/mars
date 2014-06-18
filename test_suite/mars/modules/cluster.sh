#!/bin/bash

function cluster_run
{
    cluster_check_variables
    lib_check_access_to_remote_hosts "$main_ssh_idfile_opt" \
                                     "${global_host_list[@]}"
    cluster_check_devices_all
    cluster_umount_data_device_all
    cluster_rmmod_mars_all
    cluster_create_mars_dir_all
    cluster_clear_and_mount_mars_dir_all
    cluster_clear_mars_dir_all
    cluster_create
    cluster_join
}

function cluster_umount_data_device_all
{
    local host
    local res=${resource_name_list[0]}
    for host in "${global_host_list[@]}"; do
        if mount_is_dir_mountpoint $host $(resource_get_mountpoint $res)
        then
            mount_umount $host "device_does_not_matter" $(resource_get_mountpoint $res)
        fi
    done
}

function cluster_rmmod_mars_all
{
    local host
    mount_umount_data_device_all
    for host in "${global_host_list[@]}"; do
        cluster_rmmod_mars $host
    done
}

function cluster_rmmod_mars
{
    local host=$1
    lib_vmsg "  rmmod mars on host $host"
    lib_remote_idfile $host "if grep -w mars /proc/modules; then rmmod mars; fi" || lib_exit 1
}

function cluster_clear_mars_dir_all
{
    local host
    if [ -z "$global_mars_directory" ]; then
        lib_exit 1 "  variable global_mars_directory empty"
    fi
    for host in "${global_host_list[@]}"; do
        cluster_clear_mars_dir $host
    done
}

function cluster_insert_mars_module_all
{
    local host
    for host in "${global_host_list[@]}"; do
        cluster_insert_mars_module $host
    done
}

function cluster_insert_mars_module
{
    local host=$1
    cluster_mount_mars_dir $host
    cluster_create_debugfiles $host
    lib_vmsg "  inserting mars module on $host"
    lib_remote_idfile $host 'grep -w "^mars" /proc/modules || modprobe mars' || lib_exit 1
}

function cluster_clear_mars_dir
{
    local host=$1
    if [ -z "$global_mars_directory" ]; then
        lib_exit 1 "variable global_mars_directory empty"
    fi
    lib_vmsg "  removing $host:$global_mars_directory/*"
    lib_remote_idfile $host "shopt -s dotglob && rm -rf $global_mars_directory/*" || lib_exit 1
}

function cluster_clear_and_umount_mars_dir_all
{
    local host
    for host in "${global_host_list[@]}"; do
        cluster_clear_mars_dir $host
        if mount_is_dir_mountpoint $host $global_mars_directory; then
            mount_umount $host "device_does_not_matter" $global_mars_directory || lib_exit 1
        fi
    done
}

function cluster_mount_mars_dir
{
    local host=$1
    local dev="$(lv_config_get_lv_device ${cluster_mars_dir_lv_name_list[$host]})"
    local already_mounted_correctly=0
    if mount_is_dir_mountpoint $host $global_mars_directory; then
        local mount_point
        if      mount_is_device_mounted $host $dev "mount_point" \
            &&  [ "$mount_point" == "$global_mars_directory" ]
        then
            already_mounted_correctly=1
        else
            mount_umount $host "device_does_not_matter" $global_mars_directory
        fi
    fi
    if [ $already_mounted_correctly -eq 0 ];then
        lib_rw_remote_check_device_fs $host $dev $global_mars_fs_type
        mount_mount $host $dev $global_mars_directory $global_mars_fs_type || lib_exit 1
    fi
}

function cluster_clear_and_mount_mars_dir_all
{
    local host dev
    local primary_host_to_join
    local cluster_action="create-cluster"
    for host in "${global_host_list[@]}"; do
        cluster_mount_mars_dir $host
        cluster_clear_mars_dir $host
        marsadm_do_cmd $host "$cluster_action --force" $primary_host_to_join || lib_exit 1
        cluster_action="join-cluster"
        # the first is the primary
        primary_host_to_join=${primary_host_to_join:-$host}
    done
}

function cluster_get_ip_linkname
{
    local host=$1
    echo $global_mars_directory/ips/ip-$host
}

function cluster_get_ip_linkvalue_pattern
{
    echo '^[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*$'
}

function cluster_exists
{
    local host=$1 link link_value_expected link_status

    link=$(cluster_get_ip_linkname $host)
    link_value_expected="$(cluster_get_ip_linkvalue_pattern)"

    lib_linktree_check_link $host "$link" "$link_value_expected"
    link_status=$?
    if [ $link_status -eq ${global_link_status["link_ok"]} ]; then
        lib_vmsg "  cluster on $host already exists"
        return 0
    fi
    return 1
}

function cluster_create
{
    local host=${global_host_list[0]}

    if ! cluster_exists $host; then

        marsadm_do_cmd $host "create-cluster" "" || lib_exit 1
    fi
    cluster_check_links_after_create_cluster $host
}

function cluster_join
{
    local host=${global_host_list[1]}
    local primary_host=${global_host_list[0]}

    if ! cluster_exists $host; then

        marsadm_do_cmd $host "join-cluster" $primary_host || lib_exit 1
    fi
    cluster_check_links_after_join_cluster $host $primary_host
}

function cluster_check_links_after_join_cluster
{
    local host=$1 primary_host=$2
    local link_list=("$(cluster_get_ip_linkname $primary_host)" \
                          "$(cluster_get_ip_linkname $host)")
    local link_value_expected_list=("$(cluster_get_ip_linkvalue_pattern)" \
                                    "$(cluster_get_ip_linkvalue_pattern)")
    cluster_check_ok_link_list ${#link_list[@]} "${link_list[@]}" \
                                                  "${link_value_expected_list[@]}"
}

# arguments: list_length list_of_link_names list_of_link_values
function cluster_check_ok_link_list
{
    local list_count=$1 list_name link_list link_value_expected_list i
    shift
    # filling local arrays with arguments
    for list_name in "link" "link_value_expected"; do
        for i in $(seq 1 1 $list_count); do
            eval ${list_name}_list[$i]="$1"
            shift
        done
    done

    local i link link_value_expected link_status
    for i in ${!link_list[*]}; do
        link="${link_list[$i]}"
        link_value_expected="${link_value_expected_list[$i]}"
        lib_linktree_check_link $host "$link" "$link_value_expected"
        link_status=$?
        if [ $link_status -ne ${global_link_status["link_ok"]} ]; then
            local str=$(lib_linktree_status_to_string $link_status)
            lib_exit 1 "link $host:$link has state $str"
        fi
    done
}

function cluster_check_links_after_create_cluster
{
    local host=$1 link link_value_expected link_status

    local link_list=("$(cluster_get_ip_linkname $host)")
    local link_value_expected_list=("$(cluster_get_ip_linkvalue_pattern)")

    cluster_check_ok_link_list ${#link_list[@]} "${link_list[@]}" \
                                                  "${link_value_expected_list[@]}"
}

function cluster_check_devices_all
{
    local dev host blkid_out rc
    for host in "${global_host_list[@]}"; do
        dev="$(lv_config_get_lv_device ${cluster_mars_dir_lv_name_list[$host]})"
        lib_rw_remote_check_device_fs $host $dev $global_mars_fs_type
    done
}

function cluster_create_debugfiles
{
    local host=$1
    lib_vmsg "  creating debugfile $lib_err_total_log_file"
    lib_remote_idfile $host "> $lib_err_total_log_file" || lib_exit 1
}

function cluster_remove_debugfiles
{
    local host=$1
    lib_vmsg "  removing debugfiles $lib_err_total_log_file"
    lib_remote_idfile $host "rm -f $lib_err_total_log_file" || lib_exit 1
}

function cluster_check_variables
{
    if [ ${#global_host_list[*]} -eq 0 ]; then
        lib_exit 1 "no cluster hosts given"
    fi
    if [ ${#global_host_list[*]} -ne ${#cluster_mars_dir_lv_name_list[*]} ]
    then
        lib_exit 1 "number of hosts = ${#global_host_list[*]} != ${#cluster_mars_dir_lv_name_list[*]} = number of devices"
    fi
    local lv_name
    for lv_name in ${cluster_mars_dir_lv_name_list[@]}; do
        if ! expr "(${lv_config_lv_name_list[*]})" : ".*[( ]$lv_name[ )]" >/dev/null
        then
            lib_exit 1 "lv $lv_name from cluster_mars_dir_lv_name_list = (${cluster_mars_dir_lv_name_list[*]}) not found in lv_config_lv_name_list = (${lv_config_lv_name_list[*]})"
        fi
    done
}

function cluster_create_mars_dir_all
{
    lib_vmsg "  creating mars directory $global_mars_directory on ${global_host_list[*]}"
    lib_remote_all_idfile "${global_host_list[*]}" \
           "[ -d $global_mars_directory ] || mkdir $global_mars_directory" \
                                                    || lib_exit 1
}

