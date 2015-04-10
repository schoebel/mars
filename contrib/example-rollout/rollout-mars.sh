#!/bin/bash
#
# This file is part of MARS project: http://schoebel.github.io/mars/
#
# Copyright (C) 2015 Thomas Schoebel-Theuer
# Copyright (C) 2015 1&1 Internet AG
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

############################################################

# TST spring 2015 lab prototype for mass rollout of MARS

# Environment-specific actions are encoded into variables.
# Change them (e.g. in /etc/mars/rollout.conf) for adaptation to
# any other operating environment.
#
# A few conventions are firmly built in: resource names and LVM disk names
# must be equal. In addition, it is advisable that VM names and
# resource names should be also strongly related (but VM names
# may have suffixes like infong4711.schlund.de).
#
# Please feel free to adapt this to your needs.

set -o pipefail

orig_vars="$(set | grep '^[_A-Za-z0-9]\+=' | cut -d= -f1)"

# Defaults for configuration variables
default_config=${default_config:-/etc/mars/rollout.conf}
# The rest is hardcoded here in case the config file does not exist
dry_run=${dry_run:-0}
verbose=${verbose:-0}
confirm=${confirm:-1}
help=${help:-0}
phase="{0..8}"
use_fake_sync=${use_fake_sync:-1}
override_fake_sync=${override_fake_sync:-0}
fakeable_resources="${fakeable_resources:-}"
sshopt="${sshopt:--4 -A -T -o StrictHostKeyChecking=no -o ForwardX11=no -o KbdInteractiveAuthentication=no -o VerifyHostKeyDNS=no}"
primary="${primary:-}"
secondary="${secondary:-}"
devices="${devices:-}"
device_pattern="${device_pattern:-/dev/vg*/{infong,ovz\}*}"
device_remove_regex="${device_remove_regex:-.-md\|old\|-bak}"
lvcreate_cmd="${lvcreate_cmd:-lvcreate -I 4M -L512G -n mars}"
drbd_force_unload="${drbd_force_unload:-0}"
drbd_dstate_cmd="${drbd_dstate_cmd:-drbdadm dstate}"
drbd_dstate_pattern="${drbd_dstate_pattern:-UpToDate/UpToDate}"
drbd_get_resources="${drbd_get_resources:-configure_InfongSpace.pl --list all | awk '{ print \$1; }' | sort -u}"
drbd_down_cmd="${drbd_down_cmd:-drbdadm down all || echo IGNORING failed DRBD shutdown because the kernel module will be unloaded anyway}"
drbd_update_config_res="${drbd_update_config_res:-configure_InfongSpace.pl --update-infong \$res repltype=mars}"
drbd_update_config_global="${drbd_update_config_global:-configure_InfongSpace.pl --write-drbd-conf}"
drbd_stop_cmd="${drbd_stop_cmd:-/etc/init.d/drbd stop || { ! [[ -e /proc/drbd ]] && echo stopping DRBD by hand && rmmod drbd; \}}"
mars_start_cmd="${mars_start_cmd:-ui-config-modify -c MARS_ENABLED=true; /etc/init.d/mars start}"
vm_reinit_cmd="${vm_reinit_cmd:-/etc/init.d/clustermanager restart; sleep 20; cm3 --stop all; sleep 5; cm3 -us}"
vm_status_cmd="${vm_status_cmd:-cm3 -us}"
vm_stopped_all_cmd="${vm_stopped_all_cmd:-cm3 --list-vms --with-status | grep -v '^\$' | grep -vi stopped | grep '.'}"
vm_stop_cmd="${vm_stop_cmd:-cm3 --stop all || { sleep 10; /etc/init.d/clustermanager restart && sleep 20 && cm3 --stop all; \}}"
vm_start_cmd="${vm_start_cmd:-/etc/init.d/clustermanager restart; sleep 20; cm3 --stop all; /etc/init.d/clustermanager restart; sleep 20; cm3 --stop all; cm3 -us; cm3 --start all; sleep 10; cm3 -us; for dummy in {0..2\}; do count=0; for i in \$(cm3 --list-vms --with-status | grep -i broken | cut -d: -f1); do echo \"RESTARTING BROKEN \$i\"; (( count++ )); cm3 -us; sleep 10; cm3 --stop \$i; done; if (( count )); then sleep 10; cm3 --start all; sleep 10; fi; done}"
# END configuration variables

param_vars="$(set | grep '^[_A-Za-z0-9]\+=' | cut -d= -f1)"

function fail
{
    local txt="${1:-Unkown failure}"
    echo "FAILURE: $txt" >> /dev/stderr
    exit -1
}

function do_confirm
{
    local skip="$1"
    local response

    (( !confirm )) && return 0

    [[ "$skip" != "" ]] && skip="S to skip, "
    echo -n "[CONFIRM: Press ${skip}Return to continue, ^C to abort] "
    read response
    ! [[ "$response" =~ ^[sS] ]]
    return $?
}

function remote
{
    local host="$1"
    local cmd="$2"
    local nofail="${3:-0}"

    (( verbose > 0 )) && echo "Executing on $host: '$cmd'" >> /dev/stderr
    [[ "${cmd## }" = "" ]] && return 0
    if ssh $sshopt root@$host "$cmd"; then
	return 0
    elif (( nofail )); then
	return $?
    else
	fail "ssh to '$host' command '$cmd' failed with status $?"
    fi
}

function remote_action
{
    local host="$1"
    local cmd="$2"

    if (( dry_run )); then
	echo "DRY_RUN REMOTE $host ACTION '$cmd'"
    elif (( confirm )); then
	echo "REMOTE $host ACTION '$cmd'"
	if do_confirm 1; then
	    remote "$host" "$cmd"
	else
	    echo "SKIPPING $host ACTION '$cmd'"
	fi
    else
	remote "$host" "$cmd"
    fi
}

function _get_resource
{
    local device="${1:-$(fail "Resource argument is missing")}" || exit $?
    echo "$device" | sed 's:^.*/::'
}

function are_all_vms_stopped
{
    local host="$1"
    local ret=$(remote $host "{ $vm_stopped_all_cmd ; } 1>&2 ; echo \$?")
    echo "VMs on $host are $( (( !ret )) && echo "NOT ")stopped" >> /dev/stderr
    return $(( !ret ))
}

function source_when_possible
{
    local file="$1"
    local type="$2"

    if [[ -r "$file" ]]; then
	. "$file" || fail "$type file $file is not parsable"
    fi
}

source_when_possible "$default_config" "config"

# Allow forceful override of any _known_ variable at the command line
for i; do
    if [[ "$i" =~ ^--[-_A-Za-z0-9]+$ ]]; then
	param="${i#--}"
	var="${param//-/_}"
        [[ "$(eval "echo \"\$$var\"")" = "" ]] && abort "Variable '$var' is unknown"
	eval "$var=1"
    elif [[ "$i" =~ ^--[-_A-Za-z0-9]+= ]]; then
	param="${i#--}"
	var="${param%%=*}"
	var="${var//-/_}"
	val="${param#*=}"
        [[ "$(eval "echo \"\$$var\"")" = "" ]] && abort "Variable '$var' is unknown"
	eval "$var=$val"
    elif [[ "$i" =~ ^-h$ ]]; then
	help=1
    elif [[ "$i" =~ ^-v$ ]]; then
	(( verbose++ ))
    elif [[ "$primary" = "" ]]; then
	primary="$i"
    elif [[ "$secondary" = "" ]]; then
	secondary="$i"
    else
	abort "bad parameter syntax '$i'"
    fi
done

function do_help
{
cat <<EOF
usage: $0 [options] <primaryhost> <secondaryhost>

The following parameter variables can be either passed by the
environment, or used for hard overriding on the command line
via --variable=value syntax:

$(
    declare -A orig
    for i in $orig_vars; do
	orig[$i]=1
    done
    for i in $param_vars; do
	[[ "$i" =~ _vars$ ]] && continue
	if (( !orig[$i] )); then
	    if [[ "$(eval "echo \${$i}")" =~ ^[0-9]+$ ]]; then
		echo "$i=$(eval "echo \${$i}")"
	    else
		echo "$i=\"$(eval "echo \${$i}")\""
	    fi
	fi
    done
)
EOF
}

if (( help )); then
    do_help
    exit 0
fi

if [[ "$primary" = "" ]]; then
    do_help
    fail "No primary hostname given"
fi
if [[ "$secondary" = "" ]]; then
    do_help
    fail "No secondary hostname given"
fi
[[ "$primary" = "$secondary" ]] && fail "Primary and secondary hostnames must be distinct"

function do_phase
{
    local phase="$1"
    local host

    echo ""
    echo "------- Phase $phase"
    echo ""

    case "$phase" in
	0)
	echo "Create the /mars filesystem when necessary, ensure that it is mounted"
	for host in $primary $secondary; do
	    if (( $(remote $host "ls /dev/*/mars 1>&2; echo \$?") )); then
		local line="$(remote $host "vgdisplay -c | sort -n -t: -k16 -r | head -1")" || fail "Cannot determine VG"
		local vg_name="$(echo "$line" | cut -d: -f1)"
		[[ "${vg_name// /}" = "" ]] && fail "Invalid VG name '$vg_name'"
		local pv_count="$(echo "$line" | cut -d: -f10)"
		(( pv_count < 1 )) && fail "Invalid PV count '$pv_count'"
		echo "Host $host VG '$vg_name' (has $pv_count physical volumes)"
		remote_action $host "$lvcreate_cmd -i $pv_count $vg_name"
		sleep 2
		if (( $(remote $host "ls /dev/*/mars 1>&2; echo \$?") )); then
		    fail "No LV for /mars exists on $host"
		fi
	    fi
	    if (( $(remote $host "grep -q /mars /proc/mounts; echo \$?") )); then
		remote_action $host "[[ -d /mars ]] || mkdir /mars; mount /mars || { mkfs.ext4 -L mars /dev/*/mars && mount /dev/*/mars /mars; }"
		if (( $(remote $host "grep -q /mars /proc/mounts; echo \$?") )); then
		    fail "No /mars is mounted on $host"
		fi
	    fi
	done
	;;

	1)
	echo "Create/join the MARS cluster when necessary"
	if (( $(remote $primary "ls -l /mars/uuid 1>&2; echo \$?") )); then
		echo "Host $primary create-cluster"
		remote_action $primary "marsadm create-cluster"
	fi
	if (( $(remote $secondary "ls -l /mars/uuid 1>&2; echo \$?") )); then
		echo "Host $secondary join-cluster"
		remote_action $secondary "marsadm join-cluster $primary"
	fi
	;;

	2)
	echo "Stop VMs when necessary"
	for host in $primary $secondary; do
	    if are_all_vms_stopped $host; then
		echo "No VMs are running on host $host."
	    else
		echo "Some VMs are running on host $host"
		(( !downtime_start )) && downtime_start=$(date +%s)
		remote_action $host "$vm_stop_cmd"
		downtime_end=$(date +%s)
		echo "ESTIMATED operation duration: $(( downtime_end - downtime_start )) seconds"
		if ! are_all_vms_stopped $host; then
		    fail "Some VMs are running on host $host"
		fi
	    fi
	done
	if (( downtime_start )); then
	    echo "ESTIMATED total shutdown operation duration: $(( downtime_end - downtime_start )) seconds"
	fi
	;;

	3)
	echo "Stop DRBD when necessary"
	if (( drbd_force_unload || !$(remote $primary "[[ -e /proc/drbd ]]; echo \$?") )); then
	    local drbd_res="$(remote $primary "$drbd_get_resources")" || fail "Cannot get DRBD resources on $primary"
	    echo "DRBD resources on host $primary: $(echo $drbd_res)"
	    local cmd="for i in $(echo $drbd_res); do echo -n \"\$i \"; $drbd_dstate_cmd \$i; done"
	    echo "DRBD dstate on host $primary:"
	    local tmpfile=/tmp/dstate.$primary.$$
	    remote $primary "$cmd" | tee $tmpfile
	    if grep -qv "$drbd_dstate_pattern" < $tmpfile; then
		echo "DRBD on $primary is NOT in sync"
	    else
		echo "DRBD on $primary is in sync"
	    fi
	    if (( use_fake_sync )); then
		echo "The following resources are fakeable:"
		while read res txt; do
		    echo "$res $txt"
		    fakeable_resources+=" $res"
		done <<EOF
$(grep "$drbd_dstate_pattern" < $tmpfile)
EOF
		echo "List of fakeable DRBD resources: $fakeable_resources"
	    fi
	    rm -f $tmpfile
	    for host in $primary $secondary; do
		echo "Creating DRBD backup on $host"
		remote_action $host "tar czvf /var/backups/drbd-config-$(date +%Y%m%d-%H%M).tgz /etc/drbd* || true"
		echo "Shutdown DRBD on $host"
		remote_action $host "$drbd_down_cmd"
		local res
		local cmd=""
		for res in $drbd_res; do
		    cmd+="${drbd_update_config_res/\$res/$res} ; "
		done
		cmd+="$drbd_update_config_global ; $drbd_stop_cmd"
		remote_action $host "$cmd"
	    done
	else
	    echo "DRBD is NOT in use, switching off fake-sync"
	    use_fake_sync=0
	fi
	;;

	4)
	echo "Start MARS when necessary"
	for host in $primary $secondary; do
	    if (( $(remote $host "[[ -d /proc/sys/mars ]]; echo \$?") )); then
		remote_action $host "$mars_start_cmd"
		sleep 3 &
	    else
		echo "MARS is already running on $host"
	    fi
	done
	wait

	for host in $primary $secondary; do
	    local device
	    local cmd=""
	    for device in $(eval "echo \${devices_${host//-/_}}"); do
		local res="$(_get_resource $device)"
		[[ "$res" = "" ]] && fail "Implausible resource name '$res'"
		local this_size=${sizes[$res]}
		(( this_size < 4096 )) && fail "Implausible device size '$this_size'"
		if (( $(remote $host "[[ -e /mars/resource-$res/data-$host ]]; echo \$?") )); then
		    echo "RESOURCE $res on $host: device $device size $this_size"
		    if [[ "$host" = "$primary" ]]; then
			cmd+="marsadm create-resource $res $device $res $this_size && "
		    else
			[[ "$cmd" = "" ]] && cmd="marsadm wait-cluster ; "
			cmd+="marsadm join-resource $res $device && "
		    fi
		else
		    echo "RESOURCE $res already exists on $host"
		fi
	    done
	    if [[ "$cmd" != "" ]]; then
		remote_action $host "$cmd true"
	    fi
	done
	if (( use_fake_sync )) && [[ "$fakeable_resources" != "" ]]; then
	    echo "Starting FAKE-SYNC on resources $fakeable_resources"
	    remote_action $secondary "for i in $fakeable_resources; do marsadm fake-sync \$i; done"
	elif (( override_fake_sync )); then
	    echo "OVERRIDING FAKE-SYNC on ALL resources"
	    remote_action $secondary "marsadm fake-sync all"
	else
	    echo "no fake-sync is executed"
	fi
	;;

	5)
	echo "Show status of MARS"
	for host in $primary $secondary; do
	    echo ""
	    echo "MARS Status on $host:"
	    remote $host "marsadm view all"
	done
	;;

	6)
	echo "Reinit VM clustermanager"
	for host in $primary $secondary; do
	    echo "------ Reinit $host:"
	    remote_action $host "$vm_reinit_cmd"
	done
	;;

	7)
	echo "Start VMs when necessary"
	if are_all_vms_stopped $primary; then
	    uptime_start=$(date +%s)
	    remote_action $primary "$vm_start_cmd"
	    final=$(date +%s)
	    echo "ESTIMATED startup duration: $(( final - uptime_start )) seconds"
	    if (( downtime_start )); then
		echo "ESTIMATED total VM downtime: $(( final - downtime_start )) seconds"
	    fi
	    echo ""
	else
	    echo "Some VMs are running on host $primary. Please check by hand whether some of them need a restart."
	fi
	;;

	8)
	echo "Show status of VMs"
	for host in $primary $secondary; do
	    echo "------ Status on $host:"
	    remote $host "$vm_status_cmd"
	done
	;;

	*)
	echo "Unknown / unimplemented phase '$phase'"
	;;
    esac
}

function main
{
    echo "Script $0 running phase $phase"
    echo ""
    echo "Params: $0 $*"
    echo ""
    echo "primary:   '$primary'"
    echo "secondary: '$secondary'"
    echo ""

    script_start=$(date +%s)

    for host in $primary $secondary; do
	ping -c 1 $host || fail "Host '$primary' is not reachable"
	remote $host uptime || fail "ssh connection to '$host' does not work. Ensure that ssh-agent is running."
    done
    echo ""

# when necessary, determine list of devices

    if [[ "$devices" = "" ]]; then
	for host in $primary $secondary; do
	    eval "devices_${host//-/_}=\"$(remote $host "ls $device_pattern" 2>/dev/null | grep -v "$device_remove_regex")\"" || fail "cannot determine devices on $host"
	    eval "echo devices_${host//-/_}: \${devices_${host//-/_}}"
	done
    else
	for host in $primary $secondary; do
	    eval "devices_${host//-/_}=\"$devices\""
	done
	echo "Using given devices '$devices' for both hosts $primary $secondary"
    fi

    for host in $primary $secondary; do
	[[ "$(eval "echo \${devices_${host//-/_}}")" = "" ]] && fail "No devices have been determined on $host"
	eval "resources_${host//-/_}=\"\$(for i in \${devices_${host//-/_}}; do _get_resource "\$i"; done | sort)\""
	eval "echo resources_${host//-/_}: \${resources_${host//-/_}}"
	[[ "$(eval "echo \${resources_${host//-/_}}")" = "" ]] && fail "No resources have been determined on $host"
    done
    if [[ "$(eval "echo \${resources_${primary//-/_}}")" != "$(eval "echo \${resources_${secondary//-/_}}")" ]]; then
	fail "Primary resource list is different from secondary resource list"
    fi

    declare -A sizes

    for host in $primary $secondary; do
	echo "Host $host:"
	while read device sector_size; do
	    this_size=$(( sector_size * 512 ))
	    echo "  device $device: size $this_size"
	    this_resource="$(_get_resource $device)"
	    if (( !sizes[$this_resource] || this_size < sizes[$this_resource] )); then
		sizes[$this_resource]=$this_size
	    fi
	done <<EOF
$(remote $host "/sbin/lvdisplay -c $(eval "echo \${devices_${host//-/_}}") | cut -d: -f1,7" | sed 's/:/ /')
EOF
    done

    echo ""
    echo "Determined the following sizes:"
    for res in ${!sizes[*]}; do
	echo "  $res: ${sizes[$res]}"
    done
    echo ""

    do_confirm

    for this_phase in $(eval "echo $phase"); do
	do_phase $this_phase
    done

    script_end=$(date +%s)
    echo "ESTIMATED script duration: $(( script_end - script_start )) seconds"
}

downtime_start=0
uptime_start=0

main 2>&1 | tee rollout-$(date +%Y%m%d-%H%M).$primary.$secondary.log
