#!/usr/bin/env bash
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

function install_mars_prepare
{
    install_mars_check_variables

    install_mars_check_access_to_remote_hosts \
        "${main_host_list[@]}" "$install_mars_source_host"

    # method specific actions
    case $install_mars_method in # ((
        kernel_and_modules_via_sync_from_host_to_host)
            install_mars_check_files_to_sync "$install_mars_source_host" \
                               "$install_mars_kernel_release" \
                               "${install_mars_files_to_sync_list[@]}" \
                               "${!install_mars_userspace_target_dir_list[@]}"

            local dir
            for dir in "${install_mars_userspace_target_dir_list[@]}"; do
                lib_vmsg "  checking userspace target directory $dir on hosts ${main_host_list[*]}"
                lib_remote_all_idfile "${main_host_list[*]}" "if ! test -d $dir; then mkdir -p $dir; fi" || lib_exit 1
            done
            ;;
        *) lib_exit 1 "undefined method $install_mars_method"
    esac
}

function install_mars_complete_filename_with_kernel_release
{
    local filename_desc=$1 kernel_release=$2
    echo ${filename_desc/":kernel:"/${kernel_release}}
}

function install_mars_sync_mars_and_kernel
{
    local filename_desc dirname
    declare -A files_in_dir
    for filename_desc in "${install_mars_files_to_sync_list[@]}"; do
        filename="$(install_mars_complete_filename_with_kernel_release $filename_desc $install_mars_kernel_release)"
        dirname="$(dirname $filename)"
        files_in_dir["$dirname"]+="$filename "
    done

    local host
    for host in "${main_host_list[@]}"; do
        lib_vmsg " calling depmod $install_mars_kernel_release on $host"
        lib_remote_idfile $install_mars_source_host depmod $install_mars_kernel_release || lib_exit 1
        for dirname in "${!files_in_dir[@]}"; do
            lib_vmsg "  synching $dirname from $install_mars_source_host to $host"
            lib_remote_idfile $install_mars_source_host rsync -av ${files_in_dir[$dirname]} root@$host:$dirname/ \
                                                                                                            || lib_exit 1
        done
    done
}

function install_mars_sync_userspace
{
    local host file target_dir
    for host in "${main_host_list[@]}"; do
        for file in ${!install_mars_userspace_target_dir_list[@]}; do
            target_dir=${install_mars_userspace_target_dir_list["$file"]}
            lib_vmsg "  synching $install_mars_source_host:$file to $host:$target_dir"
            lib_remote_idfile $install_mars_source_host \
                rsync -av $file root@$host:$target_dir/ || lib_exit 1
        done
    done
}

function install_mars_run
{
    install_mars_sync_mars_and_kernel
    install_mars_sync_userspace
    install_mars_update_bootloader_on_target_hosts
}

function install_mars_update_bootloader_on_target_hosts
{
    local i host boot_loader
    local label_name
    for i in "${!main_host_list[@]}"; do
        host="${main_host_list[$i]}"
        boot_loader="${main_host_bootloader_list[$i]}"
        case "$boot_loader" in # ((
           lilo) label_name="${main_host_bootloader_label_list[$i]}"
                lib_vmsg "checking label $label_name on host $host"
                lib_remote_idfile $host lilo -I $label_name || lib_exit 1
                lib_vmsg "  calling lilo on $host"
                lib_remote_idfile $host lilo || lib_exit 1
                install_mars_activate_kernel_to_boot_with_lilo $host $label_name
                ;;
              *) lib_exit 1 "bootloader $boot_loader not supported"
                ;;
        esac
    done
}

function install_mars_activate_kernel_to_boot_with_lilo
{
    local host=$1 label_name=$2
    lib_vmsg "  calling lilo -R $label_name on $host"
    lib_remote_idfile $host lilo -R $label_name || lib_exit 1
}

function install_mars_finish
{

    local target_userspace_file_list filename target_dir
    # build the list of installed userspace files on the target host
    for filename in "${!install_mars_userspace_target_dir_list[@]}"; do
        target_dir="${install_mars_userspace_target_dir_list["$filename"]}"
        target_userspace_file_list[${#target_userspace_file_list[*]}]="$target_dir/$(basename $filename)"
    done

    local host
    for host in "${main_host_list[@]}"; do
            install_mars_check_files_to_sync "$host" \
                                     "$install_mars_kernel_release" \
                                     "${install_mars_files_to_sync_list[@]}" \
                                     "${target_userspace_file_list[@]}"
            lib_vmsg "checking module mars (kernel=$install_mars_kernel_release) on $host"
            lib_remote_idfile $host \
                    modinfo -k $install_mars_kernel_release mars || lib_exit 1
    done
}

function install_mars_check_access_to_remote_hosts
{
    local hostlist="$*"

    lib_check_access_to_remote_hosts "$main_ssh_idfile_opt" $hostlist

    # method specific access checks
    case $install_mars_method in # ((
        kernel_and_modules_via_sync_from_host_to_host)
            # check access root@source_host -> root@target_hosts
            local host
            for host in "${main_host_list[@]}"; do
                lib_vmsg "  testing access from root@$install_mars_source_host to root@$host"
                lib_remote_idfile $install_mars_source_host \
                               ssh root@$host hostname || lib_exit 1
            done
            ;;
        *) lib_exit 1 "undefined method $install_mars_method"
    esac
}

function install_mars_check_files_to_sync
{
    local host=$1
    local kernel_release=$2
    shift; shift
    local files_to_sync="$@"
    local filename_desc filename cmd="ls -dl "

    lib_vmsg "  checking files to be synched on host $host"
    
    # for format of filename_desc see variable install_mars_files_to_sync_list 
    # in file default-install_mars.conf
    for filename_desc in $files_to_sync; do
        filename="$(install_mars_complete_filename_with_kernel_release $filename_desc $install_mars_kernel_release)"
        cmd+="$filename "
    done
    lib_remote_idfile $host "$cmd" || lib_exit 1
}

function install_mars_check_variables
{

    if ! [ "${install_mars_method_list["$install_mars_method"]}" -eq 1 ]; then
        lib_exit 1 "invalid method $install_mars_method"
    fi
    if [ ${#main_host_list[*]} -eq 0 ]; then
        lib_exit 1 "no target hosts given"
    fi
    if [ -z "$install_mars_kernel_release" ];then
        lib_exit 1 "no source host given"
    fi
    
    # check method specific variables
    case $install_mars_method in # ((
        kernel_and_modules_via_sync_from_host_to_host)
            local varname var
            for varname in source_host kernel_release files_to_sync_list; do
                eval var='$install_mars_'$varname
                if [ -z "$var" ];then
                    lib_exit 1 "variable $varname not set"
                fi
            done
            if [ ${#install_mars_userspace_target_dir_list[*]} -eq 0 ]; then
                lib_exit 1 "variable install_mars_userspace_target_dir_list not set"
            fi
            ;;
        *) lib_exit 1 "undefined method $install_mars_method"
    esac
}

