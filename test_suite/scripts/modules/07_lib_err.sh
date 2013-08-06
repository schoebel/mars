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


function lib_err_check_nonexistence_of_other_error_messages
{
    local host=$1 msg_file=$2 errmsg_pattern=$3
    local rc
    lib_vmsg "  checking non existence of $errmsg_pattern in $host@$msg_file"
    lib_remote_idfile $host \
                      "grep '$main_mars_errmsg_prefix' $msg_file | egrep -v '$errmsg_pattern'"
    rc=$?
    if [ $rc -eq 0 ];then
        lib_exit 1 "other errors than $errmsg_pattern found in $host@$msg_file"
    fi
}
    
function lib_err_check_and_move_global_err_files_all
{
    local host rc
    for host in "${main_host_list[@]}"; do
        lib_remote_idfile $host "test -s $lib_err_total_err_file"
        rc=$?
        if [ $rc -eq 0 ]; then
            local err_sav=$lib_err_total_err_file.$(date +'%Y%m%d%H%M%S')
            local log_sav=$lib_err_total_log_file$(date +'%Y%m%d%H%M%S')
            echo "ERROR-FILE $host:$lib_err_total_err_file (marsadm cat):" >&2
            lib_remote_idfile $host "marsadm cat $lib_err_total_err_file"
            lib_vmsg "  moving $lib_err_total_err_file to $err_sav"
            lib_remote_idfile $host "mv $lib_err_total_err_file $err_sav"
            lib_vmsg "  marsadm cat $lib_err_total_log_file > $log_sav"
            lib_remote_idfile $host \
                            "marsadm cat $lib_err_total_log_file > $log_sav"
        fi
    done
}

function lib_err_wait_for_error_messages
{
    [ $# -eq 5 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local host=$1 msg_file=$2 errmsg_pattern="$3"
    local number_errmsg_req=$4 maxwait=$5
    local count waited=0 rc

    lib_vmsg "  checking existence of file $msg_file on $host"
    lib_remote_idfile $host "ls -l --full-time $msg_file" || lib_exit 1
    while true; do
        count=$(lib_remote_idfile $host \
                "egrep '$errmsg_pattern' $msg_file | wc -l") || lib_exit 1
        lib_vmsg "  found $count messages (pattern = '$errmsg_pattern'), waited $waited"
        if [ $count -ge $number_errmsg_req ]; then
            break
        fi
        let waited+=1
        sleep 1
        if [ $waited -ge $maxwait ]; then
            lib_exit 1 "maxwait $maxwait exceeded"
        fi
    done
}

