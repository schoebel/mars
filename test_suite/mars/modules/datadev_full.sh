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

function datadev_full_run
{
    local primary_host=${global_host_list[0]}
    local secondary_host=${global_host_list[1]}
    local res=${resource_name_list[0]}
    local dev=$(lv_config_get_lv_device $res)
    local data_dev=$(resource_get_data_device $res)
    local data_dev_size_orig=$(lv_config_get_lv_size_from_name $res)
    local data_dev_size_new=$(($data_dev_size_orig + $resize_size_to_add))
    local mars_data_dev_size_new=$((data_dev_size_new \
                                    - $resize_diff_to_phsyical))
    local host

    resize_prepare

    datadev_full_dd_on_device $primary_host $data_dev \
                              $(( 1024 * ($data_dev_size_orig + 1) )) 123 1 
    resize_do_resize $primary_host $secondary_host $res $dev \
                     $data_dev_size_new $mars_data_dev_size_new

    resize_check_resize_post_conditions $primary_host $secondary_host \
                                        $res $dev $mars_data_dev_size_new ""

    resize_resize_to_orig_size $primary_host $secondary_host $dev \
                               $data_dev_size_orig


    for host in $primary_host $secondary_host; do
        lib_rw_remote_check_device_fs $host $dev ${resource_fs_type_list[$res]}
    done
}

function datadev_full_dd_on_device
{
    [ $# -eq 5 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local host=$1 dev=$2 size_mb=$3 control_nr=$4 should_fail=$5
    local bs=4096 count=$(($size_mb * 1024 / 4)) 
    local dd_out rc
    local err_msg='No space left on device'

    lib_vmsg "  filling $dev on $host (bs=$bs, count=$count)"
    dd_out=($(lib_remote_idfile $host \
         "yes $(printf '%0.1024d' $control_nr) | dd of=$dev bs=$bs conv=notrunc count=$count 2>&1"))
    rc=$?
    if [ $should_fail -eq 1 ]; then
        if [ $rc -eq 0 ]; then
            lib_exit 1 "dd ended successfully"
        fi
        if ! echo ${dd_out[@]} | grep "$err_msg" ; then
            lib_exit 1 "expected message '$err_msg' not found in ${dd_out[@]}"
        fi
    else
        if [ $rc -ne 0 ]; then
            lib_exit 1 "dd ended with rc=$rc, ${dd_out[@]}"
        fi
    fi
}

function datadev_full_get_min_required_free_space_mb
{
    local host=$1
    local f free_space free_space_sum=0
    for f in ${datadev_required_free_space_files[@]}; do
        free_space="$(lib_remote_idfile $host "cat $f")" || lib_exit 1
        if ! expr "$free_space" : '\([0-9][0-9]*\)$' >/dev/null; then
            lib_exit 1 "invalid content in $host:$f"
        fi
        let free_space_sum+=$free_space
    done
    echo $(( $free_space_sum * 1024 ))
}

function datadev_full_get_available_free_space_mb
{
    local host=$1
    local mars_lv_name=${cluster_mars_dir_lv_name_list[$host]}
    local mars_dev_size_mb=$((1024 * \
                              $(lv_config_get_lv_size_from_name $mars_lv_name)))
    local required_free_space_mb
    required_free_space_mb=$(datadev_full_get_min_required_free_space_mb \
                             $host) || lib_exit 1
    echo $(( $mars_dev_size_mb - $required_free_space_mb ))
}

