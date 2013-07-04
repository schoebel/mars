#!/bin/bash

function cluster_run
{
    cluster_check_variables
    lib_check_access_to_remote_hosts "$main_ssh_idfile_opt" \
                                     "${main_host_list[@]}"
    cluster_check_devices_all
    cluster_umount_data_device_all
    cluster_rmmod_mars_all
    cluster_create_mars_dir_all
    cluster_mount_mars_dir_all
    cluster_clear_mars_dir_all
    cluster_create
    cluster_join
}

function cluster_umount_data_device_all
{
    local host
    for host in "${main_host_list[@]}"; do
        if mount_is_dir_mountpoint $host $mount_test_mount_point; then
            mount_umount $host "device_does_not_matter" $mount_test_mount_point
        fi
    done
}

function cluster_rmmod_mars_all
{
    local host
    for host in "${main_host_list[@]}"; do
        lib_vmsg "  rmmod mars on host $host"
        lib_remote_idfile $host "if grep -w mars /proc/modules; then rmmod mars; fi" || lib_exit 1
    done
}

function cluster_clear_mars_dir_all
{
    local host
    for host in "${main_host_list[@]}"; do
        lib_vmsg "  clearing directory $host:$main_mars_directory"
        lib_remote_idfile $host "rm -rf $main_mars_directory/*" || lib_exit 1
    done
}


function cluster_mount_mars_dir_all
{
    local i host dev
    for i in "${!main_host_list[@]}"; do
        host="${main_host_list[$i]}"
        dev="$(lv_config_get_lv_device ${cluster_mars_dir_device_size_list[$i]})"
        if mount_is_dir_mountpoint $host $main_mars_directory
        then
            continue
        fi
        mount_mount $host $dev $main_mars_directory || lib_exit 1
    done
}

function cluster_get_ip_linkname
{
    local host=$1
    echo $main_mars_directory/ips/ip-$host
}

function cluster_get_ip_linkvalue_pattern
{
    echo '^[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*$'
}

function cluster_exists
{
    local host=$1 link_name link_value_expected link_status

    link_name=$(cluster_get_ip_linkname $host)
    link_value_expected="$(cluster_get_ip_linkvalue_pattern)"

    lib_linktree_check_link $host "$link_name" "$link_value_expected"
    link_status=$?
    if [ $link_status -eq ${main_link_status["link_ok"]} ]; then
        lib_vmsg "  cluster on $host already exists"
        return 0
    fi
    return 1
}

function cluster_create
{
    local host=${main_host_list[0]}

    if ! cluster_exists $host; then

        marsadm_do_cmd $host "create-cluster" "" || lib_exit 1
    fi
    cluster_check_links_after_create_cluster $host
}

function cluster_join
{
    local host=${main_host_list[1]}
    local primary_host=${main_host_list[0]}

    if ! cluster_exists $host; then

        marsadm_do_cmd $host "join-cluster" $primary_host || lib_exit 1
    fi
    cluster_check_links_after_join_cluster $host $primary_host
}

function cluster_check_links_after_join_cluster
{
    local host=$1 primary_host=$2
    local link_name_list=("$(cluster_get_ip_linkname $primary_host)" \
                          "$(cluster_get_ip_linkname $host)")
    local link_value_expected_list=("$(cluster_get_ip_linkvalue_pattern)" \
                                    "$(cluster_get_ip_linkvalue_pattern)")
    cluster_check_ok_link_list ${#link_name_list[@]} "${link_name_list[@]}" \
                                                  "${link_value_expected_list[@]}"
}

# arguments: list_length list_of_link_names list_of_link_values
function cluster_check_ok_link_list
{
    local list_count=$1 list_name link_name_list link_value_expected_list i
    shift
    # filling local arrays with arguments
    for list_name in "link_name" "link_value_expected"; do
        for i in $(seq 1 1 $list_count); do
            eval ${list_name}_list[$i]="$1"
            shift
        done
    done

    local i link_name link_value_expected link_status
    for i in ${!link_name_list[*]}; do
        link_name="${link_name_list[$i]}"
        link_value_expected="${link_value_expected_list[$i]}"
        lib_linktree_check_link $host "$link_name" "$link_value_expected"
        link_status=$?
        if [ $link_status -ne ${main_link_status["link_ok"]} ]; then
            local str=$(lib_linktree_status_to_string $link_status)
            lib_exit 1 "link $host:$link_name has state $str"
        fi
    done
}

function cluster_check_links_after_create_cluster
{
    local host=$1 link_name link_value_expected link_status

    local link_name_list=("$(cluster_get_ip_linkname $host)")
    local link_value_expected_list=("$(cluster_get_ip_linkvalue_pattern)")

    cluster_check_ok_link_list ${#link_name_list[@]} "${link_name_list[@]}" \
                                                  "${link_value_expected_list[@]}"
}

function cluster_check_devices_all
{
    local i dev host blkid_out rc
    for i in "${!main_host_list[@]}"; do
        host="${main_host_list[$i]}"
        dev="$(lv_config_get_lv_device ${cluster_mars_dir_device_size_list[$i]})"
        lib_remote_check_device_fs_idfile $host $dev
    done
}

function cluster_create_debugfiles
{
    local host=$1
    lib_vmsg "  creating debugfiles ${cluster_debugfiles[@]}"
    lib_remote_idfile $host "touch ${cluster_debugfiles[@]}" || lib_exit 1
}

function cluster_remove_debugfiles
{
    local host=$1
    lib_vmsg "  removing debugfiles ${cluster_debugfiles[@]}"
    lib_remote_idfile $host "rm -f ${cluster_debugfiles[@]}" || lib_exit 1
}

function cluster_check_variables
{
    if [ ${#main_host_list[*]} -eq 0 ]; then
        lib_exit 1 "no cluster hosts given"
    fi
    if [ ${#main_host_list[*]} -ne ${#cluster_mars_dir_device_size_list[*]} ]
    then
        lib_exit 1 "number of hosts = ${#main_host_list[*]} != ${#cluster_mars_dir_device_size_list[*]} = number of devices"
    fi
}

function cluster_create_mars_dir_all
{
    lib_vmsg "  creating mars directory $main_mars_directory on ${main_host_list[*]}"
    lib_remote_all_idfile "${main_host_list[*]}" \
           "[ -d $main_mars_directory ] || mkdir $main_mars_directory" \
                                                    || lib_exit 1
}

