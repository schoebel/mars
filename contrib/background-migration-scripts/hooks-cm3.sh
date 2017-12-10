#!/bin/bash
#
# This file is part of MARS project: http://schoebel.github.io/mars/
#
# Copyright (C) 2017 Thomas Schoebel-Theuer
# Copyright (C) 2017 1&1 Internet AG
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

###########################################

# 1&1 specific plugin / hooks for working with Jessie icpu conventions and cm3
#
# This script must be sourced from the main script.

commands_installed "curl json_pp bc"

function hook_get_mountpoint
{
    local res="$1"
    echo "/vol/$res"
}

function hook_get_hyper
{
    local res="$1"

    remote "$res" "source /lib/ui-config-framework/bash-includes; __config_getConfigVar HWNODE_NAME; echo \$HWNODE_NAME | cut -d. -f1"
}

function hook_get_store
{
    local host="$1"
    
    try="$(remote "$host" "source /lib/ui-config-framework/bash-includes; __config_getConfigVar CLUSTER_STORAGEHOST; echo \$CLUSTER_STORAGEHOST | cut -d. -f1")"
    if [[ "$try" != "" ]]; then
	echo "$try"
	return
    fi
    # fallback to nc over iscsi network
    try="$(remote "$host" "nc \$(iscsiadm -m session -o show | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+') 101 2>/dev/null | cut -d. -f1" 1)"
    if [[ "$try" != "" ]]; then
	echo "$try"
	return
    fi
    # fallback to indirect retrieval
    local hyper="$(hook_get_hyper "$host")"
    if [[ "$hyper" != "" ]] && [[ "$hyper" != "$host" ]]; then
	hook_get_store "$hyper"
    fi
}

function hook_get_vg
{
    local host="$1"
    
    remote "$host" "vgs | awk '{ print \$1; }' | grep 'vginfong\|vg[0-9]\+[ab]'"
}

function hook_resource_stop
{
    local host="$1"
    local res="$2"

    declare -g  downtime_begin
    [[ "$downtime_begin" = "" ]] && downtime_begin="$(date +%s)"
    echo "DOWNTIME BEGIN $(date)"
    # stop the whole stack
    remote "$host" "cm3 --stop $res || cm3 --stop $res || { mountpoint /vol/$res && umount /vol/$res; } || false"
}

function hook_resource_stop_vm
{
    local hyper="$1"
    local res="$2"

    declare -g  downtime_begin
    [[ "$downtime_begin" = "" ]] && downtime_begin="$(date +%s)"
    echo "DOWNTIME BEGIN $(date)"
    # stop only the vm, keep intermediate mounts etc
    remote "$hyper" "nodeagent vmstop $res"
}

function hook_resource_stop_rest
{
    local hyper="$1"
    local primary="$2"
    local res="$3"

    # stop the rest of the stack
    remote "$hyper" "nodeagent stop $res"
    local mnt="$(hook_get_mountpoint "$res")"
    remote "$hyper" "mountpoint $mnt && { umount -f $mnt ; exit \$?; } || true"
    hook_resource_stop "$primary" "$res"
}

function hook_resource_start
{
    local host="$1"
    local res="$2"

    remote "$host" "marsadm wait-cluster"
    remote "$host" "service clustermanager restart"
    remote "$host" "marsadm primary $res"
    remote "$host" "cm3 --stop $res; cm3 --start $res || { cm3 --stop $res; cm3 --start $res; } || false"
    echo "DOWNTIME END   $(date)"
    declare -g  downtime_begin
    declare -g  downtime_end="$(date +%s)"
    echo "DOWNTIME END $(date) ($(( downtime_end - downtime_begin )) s)"
    remote "$host" "if [[ -x /usr/sbin/nodeagent ]]; then /usr/sbin/nodeagent status; fi"
}

function hook_resource_check
{
    local res="$1"
    local timeout="${2:-10}"

    local host="$res"
    echo "Checking whether $host is running...."
    while ! ping -c1 $host; do
	if (( timeout-- <= 0 )); then
	    echo "HOST $host DOES NOT PING!"
	    return
	fi
	sleep 3
    done
    echo "Checking $host via check_progs ...."
    sleep 15
    remote "$host" "check_progs -cvi" 1 || echo "ATTENTION SOMETHING DOES NOT WORK AT $host"
}

###########################################

# Workarounds for firewalling (transitional => TBD)

workaround_firewall="${workaround_firewall:-1}"

function hook_prepare_hosts
{
    local host_list="$1"

    if (( workaround_firewall )); then
	local host
	for host in $host_list; do
	    remote "$host" "systemctl disable ui-firewalling.service || echo IGNORE"
	    remote "$host" "service ui-firewalling stop || /etc/init.d/firewalling stop"
	done
    fi
}

function hook_finish_hosts
{
    local host_list="$1"

    if (( workaround_firewall )); then
	local host
	for host in $host_list; do
	    remote "$host" "systemctl enable ui-firewalling.service || echo IGNORE"
	    remote "$host" "service ui-firewalling restart || /etc/init.d/firewalling restart"
	done
    fi
}

###########################################

# Workarounds for ssh between different clusters

ip_magic="${ip_magic:-1}"
do_split_cluster="${do_split_cluster:-1}"

function hook_merge_cluster
{
    local source="$1"
    local target="$2"
    [[ "$source" = "" ]] && return
    [[ "$target" = "" ]] && return

    if (( ip_magic )); then
	# This MAGIC may be needed when mutual icpu / istore
	# ssh connects via hostnames are disallowed
	# by some network firewall rules.
	# Workaround by going down to the replication IPs.
	local source_ip="$(remote "$source" "marsadm lowlevel-ls-host-ips" | grep "$source" | awk '{ print $2; }')"
	echo "Peer '$source' has IP '$source_ip'"
	source="$source_ip"
    fi
    remote "$target" "marsadm merge-cluster --ssh-port=24 $source"
}

function hook_split_cluster
{
    local host_list="$1"

    if (( do_split_cluster )); then
	local ok=0
	local host
	for host in $host_list; do
	    sleep 5
	    if remote "$host" "marsadm split-cluster --ssh-port=24" 1; then
		ok=1
		break
	    fi
	    remote "$host" "marsadm wait-cluster" 1
	done
	if (( !ok )); then
	    fail "Please run 'marsadm split-cluster --ssh-port=24' by hand"
	fi
    fi
}

function hook_join_resource
{
    local source="$1"
    local target="$2"
    local res="$3"
    local dev="$4"
    [[ "$source" = "" ]] && return
    [[ "$target" = "" ]] && return
    [[ "$res" = "" ]] && return

    remote "$target" "marsadm join-resource --ssh-port=24 $res $dev"
}

###########################################

# General checks

needed_marsadm="${needed_marsadm:-2.1 1.1}"
needed_mars="${needed_mars:-0.1stable49 0.1abeta0 mars0.1abeta0}"
max_cluster_size="${max_cluster_size:-4}"
max_syncs="${max_syncs:-2}"

function check_needed
{
    local type="$1"
    local skip_prefix="$2"
    local actual="$3"
    local needed_list="$4"

    echo "$type actual version : $actual"
    echo "$type needed versions: $needed_list"
    local needed
    for needed in $needed_list; do
	local pa="$(echo "$actual" | grep -o "^$skip_prefix")"
	local pb="$(echo "$needed" | grep -o "^$skip_prefix")"
	#echo "pa='$pa' pb='$pb'"
	if [[ "$pa" != "$pb" ]]; then
	    #echo "prefix '$pa' != '$pb'"
	    continue
	fi
	local a="$(echo "$actual" | sed "s:^$skip_prefix::" | grep -o '[0-9.]\+' | head -1)"
	local b="$(echo "$needed" | sed "s:^$skip_prefix::" | grep -o '[0-9.]\+' | head -1)"
	#echo "skip_prefix='$skip_prefix' needed='$needed' a='$a' b='$b'"
	if [[ "$a" = "" ]] || [[ "$b" = "" ]]; then
	    continue
	fi
	if [[ "$b" =~ \. ]] && [[ "${a##*.}" != "${b##*.}" ]]; then
	    continue
	fi
	if (( $(echo "$a >= $b" | bc) )); then
	    echo "$type actual version '$actual' matches '$needed'"
	    return
	fi
    done
    fail "$type actual version '$actual' does not match one of '$needed_list'"
}

function hook_check_host
{
    local host_list="$1"

    local host
    for host in $host_list; do
	local marsadm_version="$(remote "$host" "marsadm --version" | grep -o 'Version: [0-9.]*' | awk '{ print $2; }')"
	echo "Installed marsadm version at $host: '$marsadm_version'"
	check_needed "marsadm" "[0-9]\." "$marsadm_version" "$needed_marsadm"

	local mars_version="$(remote "$host" "cat /sys/module/mars/version" | awk '{ print $1; }')"
	if [[ "$mars_version" = "" ]]; then
	    fail "MARS kernel module is not loaded at $host"
	fi
	check_needed "mars kernel module" "[a-z]*[0-9.]*[a-z]*" "$mars_version" "$needed_mars"
    done

    echo "Checking that max_cluster_size=$max_cluster_size will not be exceeded at $host_list"
    local new_cluster_size="$(
        for host in $host_list; do
            remote "$host" "marsadm lowlevel-ls-host-ips" 2>/dev/null
        done | sort -u | wc -l)"
    if (( new_cluster_size < 2 )); then
	fail "Implausible new cluster size $new_cluster_size"
    fi
    echo "New cluster size: $new_cluster_size"
    if (( new_cluster_size > max_cluster_size )); then
	fail "Cluster size limit $max_cluster_size will be exceeded, aborting."
    fi

    # Check that not too much syncs are already running
    local actual_syncs=0
    for host in $host_list; do
	local count="$(remote "$host" "marsadm view-sync-rest all" | grep '^[0-9]' | grep -v '^0' | wc -l)"
	echo "There are $count syncs running at $host"
	(( actual_syncs += count ))
    done
    echo "Total number of syncs: $actual_syncs"
    echo "Max   number of syncs: $max_syncs"
    if (( max_syncs >= 0 && actual_syncs > max_syncs )); then
	fail "There are more than $max_syncs syncs running."
    fi
}

function hook_describe_plugin
{
    cat <<EOF

PLUGIN hooks-cm3

   1&1 specfic plugin for dealing with the cm3 cluster manager
   and its concrete operating enviroment (singleton instance).

   Current maximum cluster size limit: $max_cluster_size

   Maximum #syncs running before migration can start: $max_syncs

   Following marsadm --version must be installed: $needed_marsadm

   Following mars kernel modules must be loaded: $needed_mars
EOF
}

###########################################

# Mini infrastucture for access to clustermw

clustertool_host="${clustertool_host:-http://clustermw:3042}"
clustertool_user="${clustertool_user:-$(shopt -u nullglob; ls *.password | head -1 | cut -d. -f1)}" || fail "cannot find a password file *.password for clustermw"
clustertool_passwd="${clustertool_passwd:-$(cat $clustertool_user.password)}"

echo "Using clustermw username: '$clustertool_user'"

function clustertool
{
    local op="${1:-GET}"
    local path="${2:-/clusters}"
    local content="$3"

    local cmd="curl -s -u \"$clustertool_user:$clustertool_passwd\" -X \"$op\" \"$clustertool_host$path\""
    [[ "$content" != "" ]] && cmd+=" -d '${content//\'/\'}'"
    echo "$cmd" | sed -u 's/\(curl .*\)-u *[^ ]*/\1/' >> /dev/stderr
    eval "$cmd" || fail "failed REST command '$cmd'"
}

function _get_cluster_name
{
    local host="$1"

    local url="/vms/$host.schlund.de"
    [[ "$host" =~ icpu ]] && url="/nodes/$host.schlund.de"
    [[ "$host" =~ istore ]] && url="/storagehosts/$host.schlund.de"
    clustertool GET "$url" |\
	grep -o "cluster[0-9]\+" |\
	sort -u
}

function _get_segment
{
    local cluster="$1"

    local url="/clusters/$cluster"
    clustertool GET "$url" |\
	json_pp |\
	grep '"segment"' |\
	cut -d: -f2 |\
	sed 's/[ ",]//g'
}

function _get_members
{
    local cluster="$1"

    local url="/clusters/$cluster"
    clustertool GET "$url" |\
	json_pp |\
	grep -o '[-a-z0-9]\+.schlund.de' |\
	cut -d. -f1 |\
	sort -u |\
	grep -v infong
}

function hook_get_flavour
{
    local host="$1"

    clustertool GET "/nodes/$host.schlund.de" |\
	json_pp |\
	grep flavour |\
	grep -o '".*"' |\
	sed 's/"//g' |\
	sed 's/^.*: *//'
}

###########################################

# Migration operation: move cm3 config from old cluster to a new cluster

do_migrate="${do_migrate:-1}" # must be enabled; disable for dry-run testing
always_migrate="${always_migrate:-0}" # only enable for testing
# 0 = disabled
# 1 = only display the segment names
# 2 = check for equality
check_segments="${check_segments:-1}"
backup_dir="${backup_dir:-.}"

function _check_migrate
{
    local source="$1"
    local target="$2"
    local res="$3"
    [[ "$source" = "" ]] && return
    [[ "$target" = "" ]] && return
    [[ "$res" = "" ]] && return

    local source_cluster="$(_get_cluster_name "$source")" || fail "cannot get source_cluster"
    local target_cluster="$(_get_cluster_name "$target")" || fail "cannot get target_cluster"

    echo "source_cluster='$source_cluster'"
    echo "target_cluster='$target_cluster'"

    if [[ "$source_cluster" != "$target_cluster" ]]; then
	if (( check_segments )); then
	    # At the moment, cross-segment migrations won't work.
	    # TBD.
	    local source_segment="$(_get_segment "$source_cluster")" || fail "cannot get source_segment"
	    local target_segment="$(_get_segment "$target_cluster")" || fail "cannot get target_segment"
	    echo "source_segment='$source_segment'"
	    echo "target_segment='$target_segment'"
	    if (( check_segments > 1 )); then
		[[ "$source_segment" = "" ]] && fail "cannot determine source segment"
		[[ "$target_segment" = "" ]] && fail "cannot determine target segment"
		[[ "$source_segment" != "$target_segment" ]] && fail "source_segment '$source_segment' != target_segment '$target_segment'"
	    fi
	fi
    fi

}

function hook_update_cm3_config
{
    local host_list="$1"

    echo "UPDATE cm3 config on " $host_list
    echo ""

    local update_host_list="$host_list"
    local host
    local i
    for (( i = 0; i < 3; i++ )); do
	local new_host_list=""
	local status=0
	sleep 10
	for host in $update_host_list; do
	    remote "$host" "service clustermanager restart"
	done
	sleep 5
	for host in $update_host_list; do
	    timeout_cmd "remote '$host' 'cm3 --update --force'"
	    local rc=$?
	    (( status |= rc ))
	    (( rc )) && new_host_list+=" $host"
	done
	(( !status )) && break
	echo "RESTARTING cm3 update on $new_host_list"
	update_host_list="$new_host_list"
    done
    sleep 5
    for host in $host_list; do
	remote "$host" "service clustermanager restart"
    done
    sleep 3
    for host in $host_list; do
	remote "$host" "update-motd || echo IGNORE"
    done
}

function hook_migrate_cm3_config
{
    local source="$1"
    local target="$2"
    local res="$3"
    [[ "$source" = "" ]] && return
    [[ "$target" = "" ]] && return
    [[ "$res" = "" ]] && return

    local source_cluster="$(_get_cluster_name "$source")" || fail "cannot get source_cluster"
    local target_cluster="$(_get_cluster_name "$target")" || fail "cannot get target_cluster"
    if (( always_migrate )) || [[ "$source_cluster" != "$target_cluster" ]]; then
	echo "Moving config from cluster '$source_cluster' to cluster '$target_cluster'"

	local backup=""
	if [[ "$backup_dir" != "" ]]; then
	    local backup="$backup_dir/json-backup.$start_stamp"
	    mkdir -p $backup
	fi

	local status_url="/vms/$res.schlund.de"
	clustertool GET "$status_url" |\
	    log "$backup" "$res.old.raw.json" |\
	    json_pp |\
	    log "$backup" "$res.old.pp.json"

	local old_url="/clusters/$source_cluster/vms/$res.schlund.de"
	local new_url="/clusters/$target_cluster/vms/$res.schlund.de"
	echo clustertool DELETE "$old_url"
	(( do_migrate )) && clustertool DELETE "$old_url"
	echo clustertool PUT    "$new_url"
	(( do_migrate )) && clustertool PUT    "$new_url"

	clustertool GET "$status_url" |\
	    log "$backup" "$res.new.raw.json" |\
	    json_pp |\
	    log "$backup" "$res.new.pp.json"

	echo "--------------------- diff old => new ------------------"
	diff -ui $backup/$res.old.pp.json $backup/$res.new.pp.json
	echo ""
	clustertool PUT "/clusters/$source_cluster/properties/CLUSTERCONF_SERIAL"
	clustertool PUT "/clusters/$target_cluster/properties/CLUSTERCONF_SERIAL"
	echo ""

	section "Update cm3 configs"

	# Determine all hosts where a clustermanagerd _should_ be running.
	# Unfortunately, parsing the "storagehost" part will not work for standalone icpus.
	# Use a provisionary heuristics here, based on naming conventions.
	local total_list="$(
	{
	    echo "$source"
	    echo "$target"
	    for cluster in $source_cluster $target_cluster; do
		if ! _get_members $cluster | grep istore; then
		    _get_members $cluster
		fi
	    done
	} |\
		sort -u)"
	hook_update_cm3_config "$total_list"
    else
	echo "Source and target clusters are equal: '$source_cluster'"
	echo "Nothing to do."
    fi
}

function hook_check_migrate
{
    local source="$1"
    local target="$2"
    local res="$3"

    _check_migrate "$source" "$target" "$res"
}

function hook_determine_old_replicas
{
    local primary="$1"
    local res="$2"

    local primary_cluster="$(_get_cluster_name "$primary")"
    local secondary_list="$(remote "$primary" "marsadm view-resource-members $res" | { grep -v "^$primary$" || true; })" || fail "cannot determine secondary_list"
    local host
    for host in $secondary_list; do
	local cluster="$(_get_cluster_name "$host")"
	if [[ "$cluster" != "$primary_cluster" ]]; then
	    echo "FOREIGN:$host"
	fi
    done
}

function hook_determine_new_replicas
{
    local primary="$1"
    local res="$2"

    local primary_cluster="$(_get_cluster_name "$primary")"
    local secondary_list="$(remote "$primary" "marsadm view-resource-members $res" | { grep -v "^$primary$" || true; })" || fail "cannot determine secondary_list"
    local host
    for host in $primary $secondary_list; do
	local cluster="$(_get_cluster_name "$host")"
	if [[ "$cluster" = "$primary_cluster" ]]; then
	    echo "FOREIGN:$host"
	fi
    done
}

###########################################
# Local quota transfer for LXC containers.
# Problem: kuid_t implies that dump and restore is USER_NS specific,
# at least with currently used kernel + userspace tool versions.

function _get_kunden_dev
{
    local lv_name="$1"

    remote "$lv_name" "df /kunden/homepages/ | grep '^/dev' | head -1 | awk '{ print \$1; }'"
}

function hook_save_local_quota
{
    local hyper="$1"
    local lv_name="$2"

    if (( do_quota >= 2 )); then
	section "Local xfs quota dump"

	local dumpfile="$xfs_dump_dir/xfs_dump.local.$hyper.$lv_name"
	local local_dev="/dev/mars/$lv_name"
	local store="$(get_store "$lv_name")"
	echo "store='$store'"
	if [[ "$store" != "$hyper" ]]; then
	    local_dev="$(_get_kunden_dev "$lv_name")"
	    if ! [[ "$local_dev" =~ /dev/ ]]; then
		# last resort fallback, try to preserve the data for hand repair
		echo "WARNING: local device is '$local_dev'" >> /dev/stderr
		echo "WARNING: cannot determine local device for /kunden/homepages on $lv_name" >> /dev/stderr
		local_dev="/kunden/homepages"
	    fi
	fi
	echo "local_dev='$local_dev'"

	remote "$lv_name" "$xfs_dump $local_dev" > $dumpfile
	ls -l $dumpfile
	wc -l $dumpfile
    fi
}

function hook_restore_local_quota
{
    local hyper="$1"
    local lv_name="$2"

    if (( do_quota >= 2 )); then
	local dumpfile="$xfs_dump_dir/xfs_dump.local.$hyper.$lv_name"

	section "Local xfs quota restore"

	if [[ -s "$dumpfile" ]]; then
	    local max_rounds=10
	    while ! ping -c 1 "$lv_name"; do
		(( max_rounds-- < 0 )) && fail "host $lv_name does not ping"
		sleep 10
	    done
	    sleep 10

	    local local_dev="/dev/mars/$lv_name"
	    local store="$(get_store "$lv_name")"
	    echo "store='$store'"
	    if [[ "$store" != "$hyper" ]]; then
		local_dev="$(_get_kunden_dev "$lv_name")"
		if ! [[ "$local_dev" =~ /dev/ ]]; then
		    echo "Sorry, cannot determine local device for /kunden/homepages on $lv_name" >> /dev/stderr
		    return 0
		fi
	    fi
	    echo "local_dev='$local_dev'"

	    {
		echo "fs = $local_dev"
		grep -v "^fs =" < $dumpfile
	    } > $dumpfile.new
	    ls -l $dumpfile.new
	    wc -l $dumpfile.new

	    local max_rounds=10
	    while ! remote "$lv_name" "$xfs_restore $local_dev" 1 < $dumpfile.new; do
		(( max_rounds-- < 0 )) && fail "host $lv_name does not ping"
		sleep 10
	    done
	else
	    echo "LOCAL $lv_name QUOTA IS EMPTY"
	fi
    fi
}


###########################################

# Hooks for shrinking

iqn_base="${iqn_base:-iqn.2000-01.info.test:test}"
iet_type="${iet_type:-blockio}"
iscsi_eth="${iscsi_eth:-eth1}"
iscsi_tid="${iscsi_tid:-4711}"

function new_tid
{
    local iqn="$1"
    local store="$2"

    declare -g iscsi_tid

    local old_tids="$(remote "$store" "cat /proc/net/iet/volume /proc/net/iet/session" | grep -o 'tid:[0-9]\+' | cut -d: -f2 | sort -u)"
    echo "old tids: " $old_tids >> /dev/stderr
    while echo $old_tids | grep "$iscsi_tid" 1>&2; do
	(( iscsi_tid++ ))
    done
    echo "iSCSI IQN '$iqn' has new tid '$iscsi_tid'" >> /dev/stderr
    echo "$iscsi_tid"
}

function hook_disconnect
{
    local store="$1"
    local res="$2"

    local iqn="$iqn_base.$res.tmp"

    # safeguarding: retrieve any matching runtime session
    local hyper
    for hyper in $(remote "$store" "grep -A1 'name:$iqn' < /proc/net/iet/session | grep 'initiator:' | grep -o 'icpu[0-9]\+'"); do
	remote "$hyper" "iscsiadm -m node -T $iqn -u || echo IGNORE iSCSI initiator logout"
    done
    # safeguarding: retrieve any matching tid
    local tid
    for tid in $(remote "$store" "grep 'name:$iqn' < /proc/net/iet/volume | cut -d' ' -f1 | cut -d: -f2"); do
	echo "KILLING old tid '$tid' for iqn '$iqn' on '$store'"
	remote "$store" "ietadm --op delete --tid=$tid || echo IGNORE iSCSI target deletion"
    done
}

function hook_connect
{
    local store="$1"
    local hyper="$2"
    local res="$3"

    # for safety, kill any old session
    hook_disconnect "$store" "$res"

    local vg_name="$(get_vg "$store")" || fail "cannot determine VG for host '$store'"
    local dev="/dev/$vg_name/$res"
    local iqn="$iqn_base.$res.tmp"
    local iscsi_ip="$(remote "$store" "ifconfig $iscsi_eth" | grep "inet addr:" | cut -d: -f2 | awk '{print $1;}')"
    echo "using iscsi IP '$iscsi_ip'"

    # saftey check
    remote "$hyper" "ping -c1 $iscsi_ip"

    # step 1: setup stone-aged IET on storage node
    local tid="$(new_tid "$iqn" "$store")"
    remote "$store" "ietadm --op new --tid=$tid --params=Name=$iqn"
    remote "$store" "ietadm --op new --tid=$tid --lun=0 --params=Path=$dev"
    sleep 2

    # step2: import iSCSI on hypervisor
    remote "$hyper" "iscsiadm -m discovery -p $iscsi_ip --type sendtargets"
    tmp_list="/tmp/devlist.$$"
    remote "$hyper" "ls /dev/sd?" > $tmp_list
    remote "$hyper" "iscsiadm -m node -p $iscsi_ip -T $iqn -l"
    while true; do
	sleep 3
	local new_dev="$(remote "$hyper" "ls /dev/sd?" | diff -u $tmp_list - | grep '^+/' | cut -c2-)"
	[[ -n "$new_dev" ]] && break
    done
    rm -f $tmp_list
    echo "NEW_DEV:$new_dev"
}

###########################################

# Hooks for extending of XFS

function hook_extend_iscsi
{
    local hyper="$1"

    remote "$hyper" "iscsiadm -m session -R"
}
