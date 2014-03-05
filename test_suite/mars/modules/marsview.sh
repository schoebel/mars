#!/bin/bash

function marsview_get
{
    local host=$1 res=$2
    local result_line check_line
    local max_rounds=2
    local tmp_err=/tmp/xx.$$
    for (( ; ; )); do
        result_line=($(lib_remote_idfile $host marsview $res | head -1)) || lib_exit 1
        echo "result_line: ${result_line[*]}" >> /dev/stderr
        check_line=($(lib_remote_idfile $host marsadm view-1and1 $res 2> $tmp_err | head -1)) || { cat $tmp_err >> /dev/stderr; lib_exit 1; }
        cat $tmp_err >> /dev/stderr
        echo "check_line : ${check_line[*]}" >> /dev/stderr
        lib_remote_idfile $host "marsadm view-1and1 all; marsadm view-the-msg all; marsadm view-the-global-msg; true" >> /dev/stderr 2>&1 || true
        local a="$(echo "${result_line[*]}")"
        local b="$(echo "${check_line[*]}")"
        echo "a: $a" >> /dev/stderr
        echo "b: $b" >> /dev/stderr
        if [ "$a" = "$b" ]; then
            echo "COMPARE OK" >> /dev/stderr
            break
        fi
        if grep -q "SPLIT BRAIN" $tmp_err; then
            echo "COMPARE IGNORED" >> /dev/stderr
            break
        fi
        if [[ "${check_line[*]}" =~ "PrimaryUnreachable" ]]; then
            echo "COMPARE UNREACHABLE" >> /dev/stderr
            break
        fi
        sleep 1
        if (( max_rounds-- <= 0 )); then
            echo "EXCEEDED $(date)" >> /dev/stderr
            lib_remote_idfile $host "find /mars -ls; true" >> /dev/stderr 2>&1 || true
            echo "SLEEPING $(date)" >> /dev/stderr
            sleep 1
            lib_remote_idfile $host "marsadm view-1and1 all; marsadm view-the-msg all; marsadm view-the-global-msg; true" >> /dev/stderr 2>&1 || true
            local a="$(echo "${result_line[*]}" | sed 's/\[.*\]//')"
            local b="$(echo "${check_line[*]}" | sed 's/\[.*\]//')"
            if [ "$a" = "$b" ]; then
                echo "COMPARE OK" >> /dev/stderr
                echo "COMPARE FLAGS MISMATCH" >> /dev/stderr
                break
            fi
            if [[ "$a" =~ "Outdated" && "$b" =~ "Uptodate" ]]; then
                echo "COMPARE BUG" >> /dev/stderr
                break
            fi
            echo "COMPARE BAD" >> /dev/stderr
            break
        fi
    done
    rm -f $tmp_err
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

