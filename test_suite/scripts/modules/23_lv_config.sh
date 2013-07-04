#!/bin/bash

function lv_config_name_matches_our_list
{
    local lv_name=$1 size our_lv_name
    for size in ${lv_config_lv_size_list[@]}; do
        our_lv_name=$(lv_config_get_lv_name $size) || lib_exit 1
        if [ "$our_lv_name" = "$lv_name" ]; then
            lib_vmsg "  lv $lv_name found in list"
            return 0
        fi
    done
    return 1
}

function lv_config_prepare
{
    lv_config_check_variables
    if (( $lv_config_delete_lvs_not_needed )); then
        local host
        for host in  "${main_host_list[@]}"; do
            local lv_name_list
            lv_name_list=$(lib_remote_idfile $host \
                     lvdisplay $main_lvg_name -C --noheadings -o lv_name) \
                                                                    || lib_exit 1
            local lv_name
            for lv_name in ${lv_name_list[@]}; do
                if lv_config_name_matches_our_list $lv_name; then
                    continue
                else
                    lib_vmsg "  deleting lv $main_lvg_name/$lv_name on $host"
                    lib_remote_idfile $host \
                        lvremove -f $main_lvg_name/$lv_name || lib_exit 1
                fi
            done
        done
    fi
}
    
function lv_config_extract_int_from_lv_size
{
    local lv_size=$1
    expr "$lv_size" : "^ *\([0-9][0-9]*\)"
}

function lv_config_check_volume_group_existence_and_size
{
    local host lvg_size
    for host in  "${main_host_list[@]}"; do
        lib_vmsg "  checking volume group $main_lvg_name on $host"
        lvg_size=$(lib_remote_idfile $host vgs --noheadings \
                   --units G -o vg_size $main_lvg_name) || lib_exit 1
        # 11.1G -> 11
        lvg_size=$(lv_config_extract_int_from_lv_size $lvg_size)
        [ "$lvg_size" -ge $lv_config_min_lvg_size ] || \
            lib_exit 1 "size $lvg_size of volume group $main_lvg_name not >= 100"
    done
}

function lv_config_check_variables
{
    if [ $lv_config_count -eq 0 ]; then
        lib_exit 1 "number of logical volumes to be created = 0"
    fi
    if [ ${#lv_config_lv_size_list[*]} -ne $lv_config_count ];then
        lib_exit 1 "list lv_config_lv_size_list has ${#lv_config_lv_size_list[*]} elements != $lv_config_count = lv_config_count"
    fi
    local n sum
    for n in ${lv_config_lv_size_list[@]}; do
        let sum=$(($sum + $n))
    done
    if [ $sum -gt $lv_config_min_lvg_size ];then
        lib_exit 1 "sum of sizes in lv_config_lv_size_list = $sum exceeds $lv_config_min_lvg_size"
    fi

    lib_check_access_to_remote_hosts "$main_ssh_idfile_opt" \
                                     "${main_host_list[@]}"
    
    lv_config_check_volume_group_existence_and_size "${main_host_list[@]}"

}

function lv_config_resize_device
{
    local host=$1 dev=$2 lv_size_new=$3
    local lv_size_act
    lib_vmsg "  checking lv $dev on $host"
    lv_size_act=$(lv_config_get_size_logical_volume $host $dev) || lib_exit 1
    if [ $lv_size_new -ne $lv_size_act ]; then
        lib_vmsg "  resizing dev $dev on host $host to $lv_size_new"
        lib_remote_idfile $host "lvresize --force --size ${lv_size_new}G $dev" \
                                                                || lib_exit 1
    fi
}

function lv_config_get_size_logical_volume
{
    local host=$1 lv_dev=$2
    local lv_size rc
    lv_size=$(lib_remote_idfile $host lvdisplay --units G --noheadings \
              -C $lv_dev -o lv_size)
    rc=$?
    if [ $rc -ne 0 ]; then
        return $rc
    fi
    lv_size=$(lv_config_extract_int_from_lv_size $lv_size)
    echo $lv_size
}

# lv_config_delete_lvs_not_needed=1
# 
# lvdisplay /dev/vg-mars/huhu

function lv_config_recreate_logical_volumes
{
    local i host lv_name lv_size lv_dev lv_size_act rc lv_must_be_recreated
    local lv_size_tolerance lv_size_diff
    for host in "${main_host_list[@]}"; do
        for i in "${!lv_config_lv_size_list[@]}"; do
            lv_must_be_recreated=0
            lv_size=${lv_config_lv_size_list[$i]}
            lv_name=$(lv_config_get_lv_name $lv_size)
            lv_size_tolerance=$((lv_size / 10)) # 10 percent
            lv_dev=$(lv_config_get_lv_device $lv_size)
            lib_vmsg "  checking lv $lv_dev on $host"
            lv_size_act=$(lv_config_get_size_logical_volume $host $lv_dev)
            rc=$?
            if [ $rc -ne 0 ]; then
                lv_must_be_recreated=1
            else
                lv_size_diff=$(($lv_size_act - $lv_size))
                if [    -$lv_size_tolerance -gt $lv_size_diff \
                     -o $lv_size_tolerance -lt $lv_size_diff ];then
                    lib_vmsg "  removing lv $lv_dev (act. size = $lv_size_act, req. size = $lv_size) on $host"
                    lib_remote_idfile $host lvremove -f $lv_dev || lib_exit 1
                    lv_must_be_recreated=1
                fi
            fi
            if (( lv_must_be_recreated )); then
                lib_vmsg "  creating lv $lv_name (size $lv_size G) on $host"
                lib_remote_idfile $host \
                    lvcreate -L  ${lv_size}G -n $lv_name $main_lvg_name \
                                                                || lib_exit 1
            fi
        done
    done
}

function lv_config_get_lv_name
{
    local size=$1 name
    name="${main_lv_name_prefix}$size"
    echo $name
}

function lv_config_get_lv_device
{
    local size=$1
    local dev="/dev/$main_lvg_name/$(lv_config_get_lv_name $size)"
    echo $dev
}

function lv_config_run
{
    lv_config_recreate_logical_volumes
}
