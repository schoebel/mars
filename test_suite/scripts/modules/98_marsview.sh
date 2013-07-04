#!/bin/bash

function marsview_check
{
    local host=$1 res=$2 obj=$3 state_req="$4"
    local result_line field_no
    result_line=($(lib_remote_idfile $host marsview $res)) || lib_exit 1
    field_no=$(marsview_obj_to_field $obj) || lib_exit 1
    local obj_state="${result_line[$field_no]}"
    if ! expr "$obj_state" : "\($state_req\)" >/dev/null; then
        echo "$obj state $obj_state does not match $state_req = state required" >&2
        echo "marsview output: ${result_line[@]}" >&2
        return 1
    fi
    return 0
}

function marsview_obj_to_field
{
    local obj_searched=$1 obj
    for obj in "${!marsview_object_to_field_list[@]}"; do
        if [ "$obj_searched" = "$obj" ]; then
            echo ${marsview_object_to_field_list["$obj"]}
            return
        fi
    done
    lib_exit 1 "object $obj_search not valid"
}

function marsview_wait_for_state
{
    local host=$1 res=$2 obj=$3 state_req=$4 maxtime_state_constant=$5
    local waited=0
    while [ $waited -lt $maxtime_state_constant ]; do
        if marsview_check $host $res "$obj" "$state_req" ; then
            break
        fi
        lib_vmsg "  waited $waited for $obj to become $state_req"
        sleep 1
        let waited+=1
        continue
    done
    if [ $waited -ge $maxtime_state_constant ]; then
        lib_vmsg "  stopped waiting for $obj to become $state_req after $maxtime_state_constant"
        return 1
    fi
    return 0
}

