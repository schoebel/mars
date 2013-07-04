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

# starts an endless loop which copies and removes data in a given directory on 
# a remote host
# the pid of the started process will be returned in the variable named by $4
# the name of the started script will be returned in the variable named by $5
function lib_rw_write_and_delete_loop
{
    [ $# -eq 5 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local host=$1 target_dir=$2 source_dir=$3 varname_pid=$4 varname_script=$5
    local dirname dir
    local script=$lib_rw_write_and_delete_script
    lib_vmsg "  checking directories $target_dir and $source_dir on $host"
    for dirname in "target" "source"; do
        eval dir='$'$dirname'_dir'
        if [ -z "$dir" ]; then
            lib_exit 1 "directory $dirname not specified"
        fi
        lib_remote_idfile $host "test -d $dir " || \
                    lib_exit 1 "directory $host:$dir not found"
    done
    # this script will be started
    echo '#/bin/bash
while true; do
    cp -r '"$source_dir $target_dir/"'
    rm -rf '"$target_dir/$source_dir"'
done' >$script
    lib_start_script_remote_bg $host $script $varname_pid \
                                         $varname_script
    main_error_recovery_functions["lib_rw_stop_script"]="$host $script"
}

# starts an endless loop which 
# TODO function lib_rw_perf_mess

function lib_rw_stop_script
{
    local host=$1 script=$2 rc pid
    lib_vmsg "  determine pid of script $script on $host"
    pid=$(lib_remote_idfile $host pgrep -f $script)
    rc=$?
    if [ $rc -ne 0 ]; then
        main_error_recovery_functions["lib_rw_stop_script"]=
        lib_exit 1
    fi
    lib_vmsg "  stopping script $script (pid=$pid) on $host"
    lib_remote_idfile $host kill -9 $pid
    rc=$?
    if [ $rc -ne 0 ]; then
        main_error_recovery_functions["lib_rw_stop_script"]=
        lib_exit 1
    fi
    lib_vmsg "  removing files $script* on $host"
    lib_remote_idfile $host "rm -f $script*"
    main_error_recovery_functions["lib_rw_stop_script"]=
}

function lib_rw_start_writing_data_device
{
    [ $# -eq 2 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local varname_pid=$1 varname_script=$2
    lib_rw_write_and_delete_loop ${main_host_list[0]} \
                                 $mount_test_mount_point \
                                 $lib_rw_directory_to_copy_data_from \
                                 $varname_pid $varname_script
}

function lib_rw_stop_writing_data_device
{
    local script=$1
    lib_rw_stop_script ${main_host_list[0]} $script
}

function lib_rw_compare_checksums
{
    local primary_host=$1 secondary_host=$2 dev=$3
    local host role primary_cksum_out secondary_cksum_out cksum_out
    for role in "primary" "secondary"; do
        eval host='$'${role}_host
        lib_vmsg "  calculating cksum for $dev on $host"
        cksum_out="$(lib_remote_idfile $host cksum $dev)" || lib_exit 1 
        lib_vmsg "  cksum = $cksum_out"
        eval ${role}_cksum_out='"$cksum_out"'
    done
    if [ "$primary_cksum_out" != "$secondary_cksum_out" ]; then
        lib_exit 1 "cksum primary: '$primary_cksum_out' != '$secondary_cksum_out' = cksum secondary"
    fi
}

## under construction! Not needed up to now
function lib_rw_debug
{
    printf '#!/bin/bash\nsleep 10\n' >/tmp/f1
    lib_start_script_remote_bg istore-test-bs7 /tmp/f1 gix gox
    echo gix=$gix gox=$gox

    printf '#!/bin/bash\nwuerg\nsleep 10\n' >/tmp/f1
    lib_start_script_remote_bg istore-test-bs7 /tmp/f1 hix hox
    echo hix=$hix hox=$hox
    
    printf '#!/bin/bash\nwuzzl' >/tmp/f2
    lib_start_script_remote_bg istore-test-bs7 /tmp/f2 hux hax
    echo hux=$hux hax=$hax
}

function lib_rw_mount_data_device
{
    local host=$1 dev=$2 mount_point=$3
    if ! mount_is_device_mounted $host $dev; then
        mount_mount $host $dev $mount_point
    fi
}

