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

function lib_wait_until_fetch_stops
{
    [ $# -eq 6 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local module=$1 secondary_host=$2 primary_host=$3 res=$4 varname_logfile=$5
    local varname_length_logfile=$6
    local maxtime_fetch time_constant_fetch var v

    for var in maxtime_fetch time_constant_fetch; do
        eval $var='$'${module}_${var}
        eval v='$'$var
        if [ -z "$v" ]; then
            lib_exit 1 "variable $var not set"
        fi
    done

    lib_wait_internal_until_fetch_stops $secondary_host $res $primary_host \
                                        $maxtime_fetch \
                                        $time_constant_fetch \
                                        $varname_logfile $varname_length_logfile
}

function lib_wait_internal_until_fetch_stops
{
    [ $# -eq 7 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local secondary_host=$1 res=$2 primary_host=$3 maxwait=$4 inactive_wait=$5
    local varname_logfile=$6 varname_logfile_length=$7
    local inactive_waited=0 msg
    local my_logfile length file_and_length file_and_length_old="x"
    local waited=0 msg
    while [ $waited -lt $maxwait ]; do
        my_logfile=$(marsadm_get_last_logfile $secondary_host $res \
                     $primary_host) || lib_exit 1
        lib_vmsg "  get length of $secondary_host:$my_logfile"
        length=$(file_handling_get_file_length $secondary_host $my_logfile) \
                                                                || lib_exit 1
        file_and_length="$my_logfile:$length"
        if [ "$file_and_length" = "$file_and_length_old" ]; then
            let inactive_waited+=1
        else
            let inactive_waited=0
        fi
        if [ $inactive_waited -eq $inactive_wait ]; then
            break
        fi
        sleep 1
        let waited+=1
        msg="  waited $waited secs for $my_logfile act = $file_and_length, old = $file_and_length_old"
        lib_vmsg "$msg"
        file_and_length_old="$file_and_length"
    done
    if [ $waited -eq $maxwait ]; then
        lib_exit 1 "$msg"
    fi
    eval $varname_logfile_length=$length
    eval $varname_logfile=$my_logfile
}

# the value of the "action" (=$1) link will be used
# if it remains constant over $4 seconds the function returns success
function lib_wait_until_action_stops
{
    [ $# -eq 5 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local action=$1 host=$2 res=$3 maxwait=$4 inactive_wait=$5
    local waited=0 link_value link_value_old="x"
    local inactive_waited=0 msg
    local link=$(lib_linktree_get_res_host_linkname $host $res $action)
    while [ $waited -lt $maxwait ]; do
        link_value=$(lib_remote_idfile $host readlink $link) || \
                                        lib_exit 1 "cannot read link $link"
        if [ "$link_value" = "$link_value_old" ]; then
            let inactive_waited+=1
        else
            let inactive_waited=0
        fi
        if [ $inactive_waited -eq $inactive_wait ]; then
            break
        fi
        sleep 1
        let waited+=1
        msg="  waited $waited secs for $action to stop. old = $link_value_old, act = $link_value"
        lib_vmsg "$msg"
        link_value_old="$link_value"
    done
    if [ $waited -eq $maxwait ]; then
        lib_exit 1 "$msg"
    fi
}

