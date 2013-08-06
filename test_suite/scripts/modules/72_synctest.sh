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

function synctest_check_variables
{
        if [ ${#synctest_patch_length_list[@]} \
             -ne ${#synctest_number_of_patches_list[@]} ]
        then
            lib_exit 1 "  different array lengths ${#synctest_patch_length_list[@]} != ${#synctest_number_of_patches_list[@]}"
        fi
}

function synctest_run
{
    local primary_host=${main_host_list[0]}
    local secondary_host=${main_host_list[1]}
    local res=${resource_name_list[0]}
    local dev=$(lv_config_get_lv_device $res)
    local dev_size=$(lv_config_get_lv_size $res)
    local synctime i patch_length_kb no_of_patches
    local synctimes dev_to_patch time_waited

    synctest_check_variables

    lib_wait_for_initial_end_of_sync $secondary_host $res \
                                     $resource_maxtime_initial_sync \
                                     $resource_time_constant_initial_sync \
                                     "time_waited"
    lib_vmsg "  ${FUNCNAME[0]}: sync time: $time_waited"


    if [ $synctest_use_mars_sync -eq 1 ]; then
        dev_to_patch=$dev
        synctest_set_sync_modus $primary_host $secondary_host
    else
        dev_to_patch=$synctest_data_file
        synctest_generate_data_file $primary_host $secondary_host $dev \
                                        $dev_size $synctest_data_file
    fi

    if [ $synctest_parallel_writer -eq 1 ]; then
        mount_mount_data_device
        synctest_determine_write_rate $primary_host
    fi


    for i in ${!synctest_patch_length_list[@]}; do
        patch_length_in_kb=${synctest_patch_length_list[$i]}
        no_of_patches=${synctest_number_of_patches_list[$i]}
        lib_vmsg "  patchlength $patch_length_in_kb, no of patches $no_of_patches"
        if [ $synctest_use_mars_sync -eq 1 ]; then
            marsadm_do_cmd $secondary_host "down" $res || lib_exit 1
        fi

        synctest_patch_data_device $secondary_host $dev_to_patch $dev_size \
                                   $patch_length_in_kb $no_of_patches

        if [ $synctest_use_mars_sync -eq 1 ]; then

            synctest_via_mars_sync $primary_host $secondary_host $res $dev \
                                   "synctime"
        else
            synctest_via_rsync $secondary_host $primary_host \
                               $synctest_data_file "synctime"
        fi
        echo "  synctime = $synctime"
        synctimes[$i]=$synctime

    done
    echo "use_mars_sync=$synctest_use_mars_sync synctimes = ${synctimes[@]}"

    if [ $synctest_use_mars_sync -eq 0 ]; then
        synctest_remove_data_file $synctest_data_file $primary_host \
                                  $secondary_host
    fi
}

function synctest_remove_data_file
{
    local data_file=$1
    shift
    local hosts="$@" host
    for host in $hosts; do
        lib_vmsg "  removing $host:$data_file"
        lib_remote_idfile $host "rm -f $data_file" || lib_exit 1
    done
}

function synctest_determine_write_rate
{
    local host=$1 writer_pid writer_script write_count
    local res=${resource_name_list[0]}
    lib_rw_start_writing_data_device "writer_pid" "writer_script" 0 0 $res
    sleep $synctest_write_time
    lib_rw_stop_writing_data_device $writer_script "write_count"
    echo "write_count:$write_count, time_write=$synctest_write_time, rate = $(((60 * $write_count ) / $synctest_write_time)) / min"
}

function synctest_via_rsync
{
    local secondary_host=$1 primary_host=$2 data_file=$3
    local varname_time_waited=$4
    local start=$(date +'%s') time_waited

    synctest_do_rsync $secondary_host $primary_host $data_file

    time_waited=$(($(date +'%s') - $start))
    eval $varname_time_waited=$time_waited
}

function synctest_do_rsync
{
    local secondary_host=$1 primary_host=$2 data_file=$3
    lib_vmsg "  syncing $primary_host:$data_file to $secondary_host"
    lib_remote_idfile $secondary_host \
            "rsync -av -e ssh root@$primary_host:$data_file $data_file" || \
                                                                lib_exit 1
}

function synctest_via_mars_sync
{
    [ $# -eq 5 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local primary_host=$1 secondary_host=$2 res=$3 dev=$4
    local varname_time_waited=$5
    local start_sync writer_pid writer_script writer_start writer_time

    marsadm_do_cmd $secondary_host "invalidate" $res || lib_exit 1

    
    if [ $synctest_parallel_writer -eq 1 ]; then
        writer_start=$(date +'%s')
        lib_rw_start_writing_data_device "writer_pid" "writer_script" 0 0 $res
    fi

    marsadm_do_cmd $secondary_host "up" $res || lib_exit 1

    lib_wait_until_action_stops "syncstatus" $secondary_host $res \
                                  $synctest_maxtime_sync \
                                  $synctest_time_constant_sync \
                                  $varname_time_waited


    if [ $synctest_parallel_writer -eq 1 ]; then
        local write_count logfile length_logfile time_waited time_sync

        lib_rw_stop_writing_data_device $writer_script "write_count"
        writer_time=$(( $(date +'%s') - $writer_start ))

        eval time_sync='$'$varname_time_waited

        echo "write_count:$write_count, time_sync=$time_sync, rate = $(((60 * $write_count ) / $writer_time )) / min"
        lib_vmsg "  recreating all resources"
        resource_recreate_all
        
    else
        lib_rw_compare_checksums $primary_host $secondary_host $dev 0 "" ""
    fi
}

function synctest_generate_data_file
{
    [ $# -eq 5 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local primary_host=$1 secondary_host=$2 dev=$3 dev_size=$4
    local data_file=$5 file_size_in_kb=$(($dev_size * 1024 * 1024))
    local host

    lib_vmsg "  generating file $primary_host:$data_file ($file_size_in_kb KB) from $dev"
    lib_remote_idfile $primary_host \
            "dd if=$dev of=$data_file bs=1024 count=$file_size_in_kb" || \
                                                            lib_exit 1
    synctest_do_rsync $secondary_host $primary_host $data_file

    for host in $primary_host $secondary_host; do
        lib_remote_idfile $host "ls -l --full-time $data_file" || lib_exit 1
    done
}

function synctest_set_sync_modus
{
    local hosts="$@" host
    for host in $hosts; do
        lib_vmsg "  setting fast sync mode to $synctest_fast_sync on $host"
        lib_remote_idfile $host \
               "echo $synctest_fast_sync > $synctest_sync_mode_proc_file" \
                                                            || lib_exit 1
    done
}

function synctest_patch_data_device
{
    [ $# -eq 5 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local host=$1 dev=$2 dev_size_in_kb=$(($3 * 1024 * 1024))
    local patch_length_in_kb=$4 no_of_patches=$5
    local offset=0 bs=1024 remaining=$dev_size_in_kb

    while [ $offset -lt $((dev_size_in_kb - $patch_length_in_kb)) ]; do
        lib_vmsg "  patching $dev at $offset KB with $patch_length_in_kb KB"
        lib_remote_idfile $host \
            "yes :$offset: | dd of=$dev bs=$bs skip=$offset count=$patch_length_in_kb" || lib_exit 1
        offset=$(($offset + ($dev_size_in_kb / $no_of_patches)))
    done
}
