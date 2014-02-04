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

# starts an endless loop which creates and removes files in a given directory
# on remote host
# the pid of the started process will be returned in the variable named by $4
# the name of the started script will be returned in the variable named by $5
function lib_rw_write_and_delete_loop
{
    [ $# -eq 8 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local host=$1 target_file=$2 file_size_in_gb=$3 part_of_size_to_write=$4
    local varname_pid=$5 varname_script=$6 no_of_loops=$7 sleeptime=$8
    local bs=1024 
    local dd_count=$(($file_size_in_gb * 1024 * 1024 / $part_of_size_to_write))
    local dir="$(dirname $target_file)"
    local script=$lib_rw_write_and_delete_script
    lib_vmsg "  checking directory of $host:$target_file"
    dir="$(dirname $target_file)"
    lib_remote_idfile $host "test -d $dir " || \
                lib_exit 1 "directory $host:$dir not found"
    
    # this script will be started
    # after no_of_loops a sleep 1 is executed instead of the dd, because the
    # script should be explizitly killed
    # 
    # the stderror output of dd is filtered
    echo '#/bin/bash
no_of_loops='$no_of_loops'
sleeptime='$sleeptime'
count=1
while true; do
    if [ $no_of_loops -ne 0 -a $count -gt $no_of_loops ]; then
        # we do nothing more than waiting for to be killed
        sleep 1
        continue
    fi
    yes $(printf "%0.1024d" $count) | dd of='"$target_file"'.$count bs='"$bs"' count='"$dd_count"' conv=fsync status=noxfer 3>&2 2>&1 >&3 | grep -v records 3>&2 2>&1 >&3
    rm -f '"$target_file"'.*
    echo count=$count
    sleep $sleeptime
    let count+=1
done' >$script
    lib_start_script_remote_bg $host $script $varname_pid \
                                         $varname_script "rm"
    main_error_recovery_functions["lib_rw_stop_scripts"]+="$host $script "
}

function lib_rw_stop_scripts
{
    local host script rc write_count
    while [ $# -gt 0 ]; do
        host=$1
        script=$2
        shift 2
        lib_rw_stop_one_script $host $script "write_count"
        rc=$?
        main_error_recovery_functions["lib_rw_stop_scripts"]=
        if [ $rc -ne 0 ]; then
            lib_exit 1
        fi
    done
}

function lib_rw_stop_one_script
{
    local host=$1 script=$2 varname_write_count=$3
    local my_write_count grep_out rc
    lib_vmsg "  determine pid of script $script on $host"
    pid=$(lib_remote_idfile $host pgrep -f $script)
    rc=$?
    [ $rc -ne 0 ] && return $rc

    lib_vmsg "  stopping script $script (pid=$pid) on $host"
    lib_remote_idfile $host kill -9 $pid
    rc=$?
    [ $rc -ne 0 ] && return $rc

    grep_out=$(lib_remote_idfile $host \
                        "grep '^count=[0-9][0-9]*$' $script.out | tail -1")
    if [ -n "$grep_out" ]; then
        my_write_count=${grep_out#count=}
        lib_vmsg "  write_count: $my_write_count"
        eval $varname_write_count=$my_write_count
    fi
    lib_vmsg "  removing files $script* on $host"
    lib_remote_idfile $host "rm -f $script*"
}

function lib_rw_start_writing_data_device
{
    [ $# -eq 6 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local host=$1 varname_pid=$2 varname_script=$3 no_of_loops=$4 sleeptime=$5
    local res=$6
    lib_rw_write_and_delete_loop $host \
                 ${resource_mount_point_list[$res]}/$lib_rw_file_to_write \
                 $(lv_config_get_lv_size_from_name ${resource_name_list[0]}) \
                 $lib_rw_part_of_device_size_written_per_loop \
                 $varname_pid $varname_script $no_of_loops $sleeptime
}

function lib_rw_stop_writing_data_device
{
    local host=$1 script=$2 varname_write_count=$3
    lib_rw_stop_one_script $host $script $varname_write_count
}

function lib_rw_cksum
{
    local host=$1 dev=$2 varname_cksum=$3 my_cksum_out
    lib_vmsg "  calculating cksum for $dev on $host"
    my_cksum_out=($(lib_remote_idfile $host cksum $dev)) || lib_exit 1 
    lib_vmsg "  cksum = ${my_cksum_out[@]}"
    eval $varname_cksum='('${my_cksum_out[0]}' '${my_cksum_out[1]}')'
}

# if the size to compare equals 0 we take the mars size of the
# data devices
function lib_rw_compare_checksums
{
    [ $# -eq 6 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local primary_host=$1 secondary_host=$2 res=$3 cmp_size=$4
    local varname_cksum_primary=$5 varname_cksum_secondary=$6
    local dev=$(lv_config_get_lv_device $res)
    local host role primary_cksum_out secondary_cksum_out cksum_out
    local cksum_dev=$dev
    local dd_bsize=4096 dd_count
                                            
    for role in "primary" "secondary"; do
        local dummy_file
        eval host='$'${role}_host
        dummy_file=$global_mars_directory/dummy-$host
        marsadm_do_cmd $host "down" $res || lib_exit 1
        if [ $cmp_size -eq 0 ]; then
            local link_value
            local link="${resource_dir_list[$res]}/size"
            lib_vmsg "  reading link $host:$link"
            link_value=$(lib_remote_idfile $primary_host "readlink $link") || \
                                                                    lib_exit 1
            if ! expr "$link_value" : '^[0-9][0-9]*$' >/dev/null; then
                lib_exit 1 "  $link_value is not a numeric value"
            fi
            if [ $((($link_value / $dd_bsize) * $dd_bsize)) -ne $link_value ]
            then
                lib_exit 1 "value $link_value not divsible by $dd_bsize"
            fi
            dd_count=$(($link_value / $dd_bsize))
        else
            dd_count=$((($cmp_size * 1024 * 1024 * 1024) / $dd_bsize))
        fi
        lib_vmsg "  dumping $(($dd_count * $dd_bsize)) bytes of $dev to $dummy_file"
        lib_remote_idfile $host \
            "dd if=$dev of=$dummy_file bs=$dd_bsize count=$dd_count" || \
                                                                    lib_exit 1
        lib_remote_idfile $host "ls -l $dummy_file"
        cksum_dev=$dummy_file
        lib_rw_cksum $host $cksum_dev "cksum_out"
        eval ${role}_cksum_out='"${cksum_out[*]}"'
        lib_remote_idfile $host "rm -f $dummy_file" || lib_exit 1
        marsadm_do_cmd $host "up" $res || lib_exit 1
    done
    if [ "$primary_cksum_out" != "$secondary_cksum_out" ]; then
        lib_exit 1 "cksum primary: '$primary_cksum_out' != '$secondary_cksum_out' = cksum secondary"
    fi
    if [ -n "$varname_cksum_primary" ]; then
        for role in "primary" "secondary"; do
            eval eval '$varname_cksum_'$role='\"\$${role}_cksum_out\"'
        done
    fi
}

function lib_rw_mount_data_device
{
    local host=$1 dev=$2 mount_point=$3
    local res=${resource_name_list[0]}
    local mount_point
    if ! mount_is_device_mounted $host $dev "mount_point"; then
        mount_mount $host $dev $mount_point ${resource_fs_type_list[$res]} || \
                                                                    lib_exit 1
    fi
}

function lib_wait_until_replay_has_exceeded
{
    local secondary_host=$1 logfile_primary=$2 logfile_length_primary=$3 maxwait=$4

}

function lib_rw_round_to_gb
{
    local number=$1
    echo $((($number + (512 * 1024 * 1024)) / (1024 * 1024 * 1024)))
}


function lib_rw_remote_check_device_fs
{
    [ $# -eq 3 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local host=$1 dev=$2 fs_type=$3
    local tmp_dir=/mnt/mars_tmp_mountpoint
    lib_vmsg "  checking existence of directory $host:$tmp_dir"
    lib_remote_idfile $host "if test ! -d $tmp_dir; then mkdir $tmp_dir;fi" \
                                || lib_exit 1
    lib_vmsg "  checking whether $host:$dev is mountable as $fs_type filesystem on $tmp_dir"
    lib_remote_idfile $host mount -t $fs_type $dev $tmp_dir
    rc=$?
    if [ $rc -eq 0 ]; then
        mount_umount $host $dev $tmp_dir || lib_exit 1
        return
    fi
    local mount_point
    if mount_is_device_mounted $host $dev "mount_point"; then
        mount_umount $host $dev $mount_point 
    fi
    lib_vmsg "  creating $fs_type filesystem on $dev"
    lib_remote_idfile $host "mkfs.$fs_type ${lv_config_mkfs_option_list[$fs_type]} $dev" || lib_exit 1
    if [ -n "${lv_config_fs_type_tune_cmd_list[$fs_type]}" ];then
        local cmd=${lv_config_fs_type_tune_cmd_list[$fs_type]/<dev>/$dev}
        lib_vmsg "  tuning $dev on $host: $cmd"
        lib_remote_idfile $host "$cmd" || lib_exit 1
    fi
}

