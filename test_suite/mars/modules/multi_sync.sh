#!/bin/bash
# Copyright 2010-2014 Frank Liepold /  1&1 Internet AG
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

function multi_sync_run
{
    local primary_host=${global_host_list[0]}
    local secondary_host=${global_host_list[1]}
    local sync_limit
    local nr_checks # a check is done after termination of every sync_limit
                    # sync processes
    marsadm_do_cmd $secondary_host "set-sync-pref-list" \
                                   "$multi_sync_pref_list" || lib_exit 1
    for sync_limit in ${!multi_sync_required_result_list[@]}; do
        marsadm_do_cmd $secondary_host "set-sync-limit-value" \
                                       $sync_limit || lib_exit 1
        local n=${#multi_sync_required_result_list[*]} m=$sync_limit
        local check_nr
        multi_sync_init_devices $secondary_host
        # compute ceiling(n/m)
        nr_checks=$(( ($n / $m) + (($n - 1 + ($n % $m)) / $n) ))
        marsadm_do_cmd $secondary_host "invalidate" "all" || lib_exit 1
        for check_nr in $(seq 1 1 $nr_checks); do
            multi_sync_check_and_wait_for_end_of_syncs $secondary_host \
                                                       $sync_limit $check_nr
        done
    done
}

function multi_sync_init_devices
{
    local host=$1
    local resources=(${multi_sync_pref_list//,/ })
    local res
    for res in ${resources[@]}; do
        local dev=$(lv_config_get_lv_device $res)
        lib_vmsg "  writing $dev on $host"
        # only the first 128 MB will be overwritten
        local dd_bs=4096 dd_count=$((256*512))
        lib_remote_idfile $host \
            "yes hihi | dd of=$dev oflag=direct bs=4096 count=$((256*128))" || \
                                                        lib_exit 1
    done
}

function multi_sync_check_and_wait_for_end_of_syncs
{
    local host=$1 sync_limit=$2 check_nr=$3
    local nr_syncs_running_req nr_syncs_running_act
    local nr_syncs_wanted_req nr_syncs_wanted_act
    local result="${multi_sync_required_result_list[$sync_limit]}"
    local maxwait=10 waited=0
    local ssh_out i
    local syncing_resources
    if [ -z "$result" ]; then
        lib_exit 1 "missing value for key $sync_limit in multi_sync_required_result_list"
    fi
    nr_syncs_wanted_req=$(multi_sync_get_result_entry \
                                "wanted" "$result" "$check_nr") || lib_exit 1
    nr_syncs_running_req=$sync_limit
    if [ $nr_syncs_wanted_req -lt $sync_limit ]; then # last set of syncs
        nr_syncs_running_req=$nr_syncs_wanted_req
    fi
    syncing_resources="$(multi_sync_get_result_entry \
                            "resources" "$result" "$check_nr")" || lib_exit 1
    lib_vmsg "  checking running syncs sync_limit=$sync_limit,check_nr=$check_nr,res=$syncing_resources,running_req=$nr_syncs_running_req,wanted_req=$nr_syncs_wanted_req"
    while true; do
        ssh_out=($(lib_remote_idfile $host \
                  "cat $multi_sync_nr_syncs $multi_sync_nr_wanted_syncs")) || \
                                                                lib_exit 1
        nr_syncs_running_act=${ssh_out[0]}
        nr_syncs_wanted_act=${ssh_out[1]}
        if [ $nr_syncs_running_act -eq $nr_syncs_running_req \
             -a $nr_syncs_wanted_act -eq $nr_syncs_wanted_req ]
        then
            break
        fi
        sleep 1
        let waited+=1
        lib_vmsg "  waited $waited for check to succeed: nr_syncs_running_act=$nr_syncs_running_act,nr_syncs_running_req=$nr_syncs_running_req,nr_syncs_wanted_act=$nr_syncs_wanted_act,nr_syncs_wanted_req=$nr_syncs_wanted_req"
        if [ $waited -eq $maxwait ]; then
            lib_exit 1 "maxwait $maxwait exceeded"
        fi
    done
    multi_sync_wait_for_end_of_syncs $secondary_host $syncing_resources
}

# fetch correct entry from a result line of multi_sync_required_result_list
# which is of the form
# lv-3-2,lv-1-2,lv-2-2:3,2,1
function multi_sync_get_result_entry
{
    local entry_type="$1" entry="$2" check_nr=$3
    local retval i
    # split at :
    case "$entry_type" in # (((
        resources) retval=${entry%:*};;
        wanted) retval=${entry#*:};;
        *) lib_exit 1 "wrong entry_type $entry_type";;
    esac
    # remove comma terminated prefixes to find correct value
    for i in $(seq 1 1 $(($check_nr - 1))); do
        retval=${retval#*,}
        if [ -z "$retval" ]; then
            lib_exit 1 "wrong entry $entry, check_nr=$check_nr, i=$i"
        fi
    done
    retval=${retval%%,*}
    if [ -z "$retval" ]; then
        lib_exit 1 "cannot determine value in $entry, check_nr=$check_nr"
    fi
    case "$entry_type" in # (((
        resources) echo ${retval//|/ };;
        wanted) echo $retval;;
    esac
}        

function multi_sync_wait_for_end_of_syncs
{
    local host=$1
    shift
    local syncing_resources="$*"
    local res diskstate maxwait=600 waited=0
    for res in $syncing_resources; do
        while true; do
            lib_vmsg "  checking diskstate of $res on $host"
            diskstate=$(lib_remote_idfile $host \
                         "marsadm view-diskstate-1and1 $res") || lib_exit 1
            if [ "$diskstate" = "Uptodate" ]; then
                break
            fi
            sleep 1
            let waited+=1
            lib_vmsg "  waited $waited for disk of res $res to become Uptodate (act=$diskstate)"
            if [ $waited -eq $maxwait ]; then
                lib_exit 1 "maxwait $maxwait exceeded"
            fi
        done
    done
}
