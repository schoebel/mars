#!/bin/bash

function marsview_get
{
    local host=$1 res=$2
    local result_line check_line
    local max_rounds=10
    local tmp_err=/tmp/xx.$$
    rm -f $tmp_err || lib_exit 1
    for (( ; ; )); do
        result_line=($(lib_remote_idfile $host marsview $res | head -1)) || \
                                                                    lib_exit 1
        lib_vmsg "  result_line: ${result_line[*]}"
        check_line=($(lib_remote_idfile $host marsadm view-1and1 $res \
                    2>$tmp_err | head -1)) || \
                    { cat $tmp_err >&2; lib_exit 1; }
        if [ -s $tmp_err ]; then
            lib_vmsg "   marsadm view-1and1 had errors:"
            cat $tmp_err >&2
        fi
        [ "${result_line[*]}" = "${check_line[*]}" ] && break
        lib_vmsg "  check_line : ${check_line[*]}" >&2
        grep -q "SPLIT BRAIN" $tmp_err && break
        [[ "${check_line[*]}" =~ "PrimaryUnreachable" ]] && break
        sleep 2
        if (( max_rounds-- <= 0 )); then
            lib_vmsg "  COMPARE BAD" >&2
            break
        fi
        (( max_rounds-- )) || break
    done
    rm -f $tmp_err || lib_exit 1
    echo "${result_line[*]}"
}

function marsview_check
{
    local host=$1 res=$2 obj=$3 state_req="$4"
    local result_line field_no
    result_line=($(marsview_get $host $res))
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
    lib_vmsg "  waiting for $obj to become $state_req on $host"
    while [ $waited -lt $maxtime_state_constant ]; do
        if marsview_check $host $res "$obj" "$state_req" ; then
            break
        fi
        lib_vmsg "  waited $waited for $obj to become $state_req on $host"
        sleep 1
        let waited+=1
        continue
    done
    if [ $waited -ge $maxtime_state_constant ]; then
        lib_vmsg "  stopped waiting for $obj to become $state_req on $host after $maxtime_state_constant"
        lib_linktree_print_linktree $host
        return 1
    fi
    return 0
}

