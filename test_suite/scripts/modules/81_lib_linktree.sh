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

function lib_linktree_get_designated_primary_linkname
{
    local res=$1
    echo ${resource_dir_list[$res]}/primary
}

function lib_linktree_get_primary_linkname
{
    local host=$1 res=$2
    echo ${resource_dir_list[$res]}/actual-$host/is-primary
}

function lib_linktree_get_res_host_linkname
{
    local host=$1 res=$2 action=$3
    echo ${resource_dir_list[$res]}/$action-$host
}

function lib_linktree_print_linktree
{
    local host=$1
    lib_vmsg "lamport clock on $host:"
    lib_remote_idfile $host 'cat /proc/sys/mars/lamport_clock'
    lib_vmsg "printing link tree on $host"
    lib_remote_idfile $host 'ls -l --full-time $(find /'"$main_mars_directory"' \! -type d | sort)'
}

# the required link value may be specified with an unit (e.g. 3G)
function lib_linktree_check_link_int_value
{
    [ $# -eq 5 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local host=$1 res=$2 link=$3 link_value_req=$4 value_unit=$5
    local link link_value_act waited=0
    link_value_req=$(lv_config_extract_int_from_lv_size_with_unit $link_value_req)
    case $link in #((
        size) link="${resource_dir_list[$res]}/$link"
          ;;
        sync) link="${resource_dir_list[$res]}/todo-$host/$link"
          ;;
           *) link="$(lib_linktree_get_res_host_linkname $host $res \
                                                              $link)"
          ;;
    esac
    while true; do
        lib_vmsg "  reading link $host:$link"
        link_value_act=$(lib_remote_idfile $host "readlink $link") || \
                                                                        lib_exit 1
        if ! expr "$link_value_act" : '^[0-9][0-9]*$' >/dev/null; then
            lib_exit 1 "  $link_value_act is not a numeric value"
        fi
        # rounding
        local rounded=$(( ($link_value_act + ( $value_unit / 2 )) / $value_unit ))
        if [ $rounded -ne $link_value_req ]; then
            echo " $host:$link: value req. = $link_value_req != $rounded = rounded (unit = $value_unit) $link_value_act = value act." >&2
            if [ $waited -ge $lib_linktree_maxtime_to_wait_for_link_value ]
            then
                lib_exit 1 "  max. wait time $lib_linktree_maxtime_to_wait_for_link_value exceeded"
            else
                sleep 1
                let waited+=1
                lib_vmsg "  waited $waited for $link to take $link_value_req"
                continue
            fi
        else
            break
        fi
    done
}


# link_value_expected may be a expr pattern
function lib_linktree_check_link
{
    local host=$1 link=$2 link_value_expected=$3
    local link_value rc link_readable=0 link_values_equal=0
    local waited=0
    while true; do
        lib_vmsg "  checking link $link (value expected = $link_value_expected) on $host"
        link_value=$(lib_remote_idfile $host "readlink $link")
        rc=$?
        echo "  link $host:$link -> $link_value"
        if [ $rc -eq 0 ]; then
            if ! expr "$link_value" : "$link_value_expected" >/dev/null; then
                if [ $waited -ge $lib_linktree_maxtime_to_wait_for_link_value ]
                then
                    lib_vmsg "  max. wait time $lib_linktree_maxtime_to_wait_for_link_value exceeded"
                    return ${main_link_status["link_has_wrong_value"]}
                else
                    sleep 1
                    let waited+=1
                    lib_vmsg "  waited $waited for $link to become $link_value_expected"
                    continue
                fi
            else
                return ${main_link_status["link_ok"]}
            fi
        else
            return ${main_link_status["link_does_not_exist"]}
        fi
    done
    lib_exit 1 "this code should not be reached"
}

function lib_linktree_status_to_string
{
    local link_status=$1 status
    for status in "${!main_link_status[@]}"; do
        if [ ${main_link_status["$status"]} = "$link_status" ]; then
            echo $status
            return
        fi
    done
    lib_exit 1 "undefined link_status $link_status"
}





