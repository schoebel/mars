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

function multires_prepare
{
    cluster_umount_mars_dir_all
    lv_config_prepare
    lv_config_run
    cluster_mount_mars_dir_all
    resource_rm_resource_dir_all
    cluster_create
    cluster_join
    cluster_insert_mars_module_all
    multires_create_resources_all
}

function multires_create_resources_all
{
    local primary_host=${main_host_list[0]}
    local secondary_host=${main_host_list[1]}
    local res lv_dev count=0 maxwait=20
    for res in ${lv_config_name_list[@]}; do
    	local lv_dev=$(lv_config_get_lv_device $res)
        marsadm_do_cmd $primary_host "create-resource --force" "$res $lv_dev"
        marsadm_do_cmd $primary_host "wait-resource" "$res is-device"
        lib_remote_idfile $primary_host marsview $res
        marsadm_do_cmd $secondary_host "join-resource --force" "$res $lv_dev"
        lib_remote_idfile $secondary_host marsview $res
        while true;do
    	    if marsview_check $secondary_host $res "repl" "-S..-" \
	       && marsview_check $secondary_host $res "disk" "Inconsistent"
	    then
                marsadm_do_cmd $secondary_host "pause-sync" $res
                marsadm_do_cmd $secondary_host "fake-sync" $res
                marsadm_do_cmd $secondary_host "resume-sync" $res
                continue
            fi
    	    if marsview_check $secondary_host $res "repl" "-SFA-" \
	       && marsview_check $secondary_host $res "disk" "Uptodate"
            then
                break;
            fi
            sleep 1
            let count+=1
            if [ $count -ge $maxwait ]; then
                lib_exit 1 "maxwait $maxwait exceeded"
            fi
            lib_vmsg "  waited $count for secondary to become up to date"
            if marsview_check $secondary_host $res "disk" "Detached"; then
                lib_vmsg "  try to join $res again"
                marsadm_do_cmd $secondary_host "join-resource --force" $res \
		                                                       $lv_dev
            fi
        done
    done
}
