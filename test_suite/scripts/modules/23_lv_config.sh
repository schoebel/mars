#!/bin/bash

function lv_config_name_matches_our_list
{
    local lv_name=$1 res
    for res in ${lv_config_lv_name_list[@]}; do
        if [ "$res" = "$lv_name" ]; then
            lib_vmsg "  lv $lv_name found in list"
            return 0
        fi
    done
    return 1
}

function lv_exists
{
    local host=$1 lv_name=$2 
    local dev=$(lv_config_get_lv_device $lv_name)
    lib_vmsg " checking whether lv $lv_name (dev=$dev) on $host exists"
    lib_remote_idfile $host "lvdisplay --noheadings -C $dev -o lv_name"
    return $?
}

function lv_config_prepare
{
    lv_config_check_variables
    cluster_rmmod_mars_all
    cluster_clear_and_umount_mars_dir_all
    lv_config_delete_vg
}

function lv_config_delete_vg
{
    local host out i rc
    for host in  "${main_host_list[@]}"; do
        if [ ${lv_config_vg_recreatable_list[$host]} -eq 1 ]; then
            lib_vmsg "  removing lvs in $lv_config_lvg_name on $host"
            out="$(lib_remote_idfile $host lvdisplay -c $lv_config_lvg_name)"
            rc=$?
            # rc=5 means: vg does not exist
            if [ $rc -ne 5 -a $rc -ne 0 ]; then
                    lib_exit 1
            fi
            for i in $(echo "$out" | \
                       awk -F':' '$2=="'$lv_config_lvg_name'"{print $1}')
            do
                    lv_config_lvremove $host $i
            done
            lib_vmsg " removing pvs in $lv_config_lvg_name on $host"
            out="$(lib_remote_idfile $host pvdisplay -c)" || lib_exit 1
            for i in $(echo "$out" | \
                        awk -F':' '$3=="'$lv_config_lvg_name'"{print $1":"$2}
                                   $2=="'$lv_config_lvg_name'"{print $1}'
                      )
            do
                    lib_vmsg " removing pvs $host:$i"
                    lib_remote_idfile $host pvremove -ff -y $i || lib_exit 1
            done
        else
            lib_vmsg "  vg $lv_config_lvg_name will not be recreated on $host"
        fi
                            
    done
}

function lv_config_lvremove
{
    local host=$1 logical_volume_path=$2
    lib_vmsg "lvremove $host:$logical_volume_path"
    lib_remote_idfile $host lvremove -f $logical_volume_path || lib_exit 1
}
    
# removes decimal places and trailing unit letters (e.g. 9G -> 9)
function lv_config_extract_int_from_lv_size_with_unit
{
    local lv_size_with_unit=$1
    expr "$lv_size_with_unit" : "^ *\([0-9][0-9]*\)"
}

function lv_config_check_volume_group_existence_and_size
{
    local host lvg_size_with_unit rc
    for host in  "${main_host_list[@]}"; do
        lib_vmsg "  checking volume group $lv_config_lvg_name on $host"
        lvg_size_with_unit=$(lib_remote_idfile $host vgs --noheadings \
                             --units G -o vg_size $lv_config_lvg_name)
        rc=$?
        if [ $rc -ne 0 ];then
            lib_vmsg "  vg $host:$lv_config_lvg_name will be created"
            return
        fi
        # 11.1G -> 11
        local lvg_size
        lvg_size=$(lv_config_extract_int_from_lv_size_with_unit \
                             $lvg_size_with_unit)
        [ "$lvg_size" -ge $lv_config_min_lvg_size ] || \
            lib_exit 1 "size $lvg_size of volume group $lv_config_lvg_name not >= $lv_config_min_lvg_size"
    done
}

function lv_config_check_variables
{
    if [ ${#lv_config_lv_name_list[*]} -eq 0 ]; then
        lib_exit 1 "number of logical volumes to be created = 0"
    fi
    local lv_name sum
    for lv_name in ${lv_config_lv_name_list[@]}; do
        let sum=$(($sum + $(lv_config_get_lv_size_from_name $lv_name)))
    done
    if [ $sum -gt $lv_config_min_lvg_size ];then
        lib_exit 1 "sum of sizes in lv_config_lv_name_list = $sum greater than $lv_config_min_lvg_size"
    fi

    local host
    for host in  "${main_host_list[@]}"; do
        if [ -z "${lv_config_vg_recreatable_list[$host]}" ]; then
            lib_exit 1 "host $host is missing in array lv_config_vg_recreatable_list"
        fi
    done
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
    if [ $lv_size_new -eq $lv_size_act ]; then
        return
    elif [ $lv_size_new -gt $lv_size_act ]; then
        lib_vmsg "  resizing dev $dev on host $host to $lv_size_new"
        lib_remote_idfile $host "lvresize --force --size ${lv_size_new}G $dev" \
                                                                || lib_exit 1
    else # instead of shrinking we rebuild the lv, because shrinking can end up
         # in a volume size different from the size obtained by creation of the lv
        local lv_name=$(lv_config_get_lv_name $dev)
        lib_vmsg "  lv $host:$lv_name (dev=$dev): act. size = $lv_size_act, req. size = $lv_size_new"
        lv_config_lvremove $host $dev
        lv_config_create_lv $host $lv_name
    fi
}
    
function lv_config_get_lv_name
{
    local dev=$1
    echo ${dev##*/}
}

function lv_config_get_size_logical_volume
{
    local host=$1 lv_dev=$2
    local lv_size_with_unit rc lv_size
    lv_size_with_unit=$(lib_remote_idfile $host lvdisplay --units G \
                        --noheadings -C $lv_dev -o lv_size)
    rc=$?
    if [ $rc -ne 0 ]; then
        return $rc
    fi
    lv_size=$(lv_config_extract_int_from_lv_size_with_unit $lv_size_with_unit)
    echo $lv_size
}

function lv_config_recreate_logical_volumes
{
    local create_volume_group_too=$1 host lv_name
    for host in "${main_host_list[@]}"; do
        if [ $create_volume_group_too -eq 1 ]; then
            if [ ${lv_config_vg_recreatable_list[$host]} -eq 0 ]; then
                lib_vmsg "  skipping recreation of vg $lv_config_lvg_name on $host"
            else
                lv_config_create_vg $host
            fi
        fi
        for lv_name in "${lv_config_lv_name_list[@]}"; do
	        lv_config_recreate_lv $host $lv_name
        done
    done
}

function lv_config_recreate_lv
{
    local host=$1 lv_name=$2
    local lv_size lv_dev lv_size_act rc lv_must_be_recreated
    local lv_size_tolerance lv_size_diff
    lv_must_be_recreated=0
    lv_size=$(lv_config_get_lv_size_from_name $lv_name)
    lv_size_tolerance=$((lv_size / 10)) # 10 percent
    lv_dev=$(lv_config_get_lv_device $lv_name)
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
        lv_config_create_lv $host $lv_name
    fi
}

function lv_config_create_lv
{
    local host=$1 lv_name=$2
    local size=$(lv_config_get_lv_size_from_name $lv_name)
    local partition_count=$(echo ${lv_config_partition_list[$host]} | wc -w)
    if [ -z "$partition_count" -o "$partition_count" = "0" ]; then
        lib_exit 1 "missing value in lv_config_partition_list for host $host"
    fi
    lib_vmsg "  creating lv $lv_name (size $size G) on $host"
    lib_remote_idfile $host \
            lvcreate -n $lv_name \
            -i $partition_count \
            -I $lv_config_stripesize -L ${size}G $lv_config_lvg_name \
                                                                || lib_exit 1
}

function lv_config_create_vg
{
    local host=$1
    local lv
    local partitions="${lv_config_partition_list[$host]}"
    lib_vmsg "  creating $lv_config_lvg_name on $host (partitions=$partitions)"
    lib_remote_idfile $host vgcreate $lv_config_lvg_name $partitions \
                                    || lib_exit 1
    for lv in ${lv_config_lv_name_list[@]}; do
        lv_config_create_lv $host $lv
    done
}

function lv_config_get_lv_size_from_name
{
    local lv_name=$1
    echo ${lv_name##*-}
}

function lv_config_get_lv_device
{
    local lv_name=$1
    local dev="/dev/$lv_config_lvg_name/$lv_name"
    echo $dev
}

function lv_config_run
{
    lv_config_recreate_logical_volumes 1
}

function lv_config_get_dm_dev
{
    local host=$1 dev=$2
    local dm_dev rc
    dm_dev=$(lib_remote_idfile $host  "dmsetup info -C --noheadings -o name $dev")
    rc=$?
    if [ $rc -ne 0 ]; then
        return $rc
    fi
    lib_remote_idfile $host "ls /dev/mapper/$dm_dev" || lib_exit 1
}
