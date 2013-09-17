#!/bin/bash

function lv_config_name_matches_our_list
{
    local lv_name=$1 res
    for res in ${lv_config_name_list[@]}; do
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
    resource_leave_all
    cluster_umount_mars_dir_all
    lv_config_delete_vg
}

function lv_config_delete_vg
{
    local host out i rc
    for host in  "${main_host_list[@]}"; do
	lib_vmsg "  removing lvs in $main_lvg_name on $host"
	out="$(lib_remote_idfile $host lvdisplay -c $main_lvg_name)"
	rc=$?
	# rc=5 means: vg does not exist
	if [ $rc -ne 5 -a $rc -ne 0 ]; then
		lib_exit 1
	fi
	for i in $(echo "$out" | awk -F':' '$2=="'$main_lvg_name'"{print $1}')
	do
		lib_vmsg "lvremove $host:$i"
		lib_remote_idfile $host lvremove -f $i || lib_exit 1
	done
	lib_vmsg " removing pvs in $main_lvg_name on $host"
	out="$(lib_remote_idfile $host pvdisplay -c)" || lib_exit 1
	for i in $(echo "$out" | \
		    awk -F':' '$3=="'$main_lvg_name'"{print $1":"$2}
		               $2=="'$main_lvg_name'"{print $1}'
		  )
	do
		lib_vmsg " removing pvs $host:$i"
		lib_remote_idfile $host pvremove -ff -y $i || lib_exit 1
	done
	    		
    done
}

    
function lv_config_extract_int_from_lv_size
{
    local lv_size=$1
    expr "$lv_size" : "^ *\([0-9][0-9]*\)"
}

function lv_config_check_volume_group_existence_and_size
{
    local host lvg_size rc
    for host in  "${main_host_list[@]}"; do
        lib_vmsg "  checking volume group $main_lvg_name on $host"
        lvg_size=$(lib_remote_idfile $host vgs --noheadings \
                   --units G -o vg_size $main_lvg_name)
	rc=$?
	if [ $rc -ne 0 ];then
	    lib_vmsg "  vg $host:$main_lvg_name will be created"
	    return
	fi
        # 11.1G -> 11
        lvg_size=$(lv_config_extract_int_from_lv_size $lvg_size)
        [ "$lvg_size" -ge $lv_config_min_lvg_size ] || \
            lib_exit 1 "size $lvg_size of volume group $main_lvg_name not >= $lv_config_min_lvg_size"
    done
}

function lv_config_check_variables
{
    if [ ${#lv_config_name_list[*]} -eq 0 ]; then
        lib_exit 1 "number of logical volumes to be created = 0"
    fi
    local lv_name sum
    for lv_name in ${lv_config_name_list[@]}; do
        let sum=$(($sum + $(lv_config_get_lv_size $lv_name)))
    done
    if [ $sum -le $lv_config_min_lvg_size ];then
        lib_exit 1 "sum of sizes in lv_config_name_list = $sum smaller than $lv_config_min_lvg_size"
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

function lv_config_recreate_logical_volumes
{
    local host lv_name lv_size lv_dev lv_size_act rc lv_must_be_recreated
    local lv_size_tolerance lv_size_diff
    lv_config_create_vg
    for host in "${main_host_list[@]}"; do
        for lv_name in "${lv_config_name_list[@]}"; do
            lv_must_be_recreated=0
            lv_size=$(lv_config_get_lv_size $lv_name)
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
        done
    done
}

function lv_config_create_lv
{
    local host=$1 lv_name=$2
    local size=$(lv_config_get_lv_size $lv_name)
    lib_vmsg "  creating lv $lv_name (size $size G) on $host"
    lib_remote_idfile $host \
    		lvcreate -n $lv_name \
			-i ${lv_config_partition_count_list[$host]} \
			-I $lv_config_stripesize -L ${size}G $main_lvg_name \
                                                                || lib_exit 1
}

function lv_config_create_vg
{
    local host
    for host in "${main_host_list[@]}"; do
	local lv
	local partitions="${lv_config_partition_list[$host]}"
	lib_vmsg "  creating $main_lvg_name on $host (partitions=$partitions)"
	lib_remote_idfile $host vgcreate $main_lvg_name $partitions \
								    || lib_exit 1
	for lv in ${lv_config_name_list[@]}; do
	    lv_config_create_lv $host $lv
	done
    done
}

function lv_config_get_lv_size
{
    local lv_name=$1
    echo ${lv_name##*-}
}

function lv_config_get_lv_device
{
    local lv_name=$1
    local dev="/dev/$main_lvg_name/$lv_name"
    echo $dev
}

function lv_config_run
{
    lv_config_recreate_logical_volumes
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
