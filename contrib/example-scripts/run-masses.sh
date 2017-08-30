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

# TST autumn 2015 lab prototype
# for mass switchover and other generic mass commands

# Environment-specific actions are encoded into variables.
# Change them (e.g. in /etc/mass-actions/mass-actions.conf) for
# adaptation to any other operating environment.
#
# In addition, you will need an association file host-assoc.txt
# containing 2 fields separated by colon: first the hostname, second
# an arbitrary key value with an arbitrary meaning. It is wise to
# use locations, room numbers, rack numbers, etc for that field.
# What exactly is up to you. Multiple keys may be assigned to the same
# host.
#
# Please feel free to adapt this to your needs.

set -o pipefail
shopt -s nullglob
export LC_ALL=C
export start_stamp="$(date "+%F_%T" | sed 's/:/./g')"

declare -A doc
orig_vars="$(set | grep '^[_A-Za-z0-9]\+=' | cut -d= -f1)"

# START defaults for configuration variables

default_config="${default_config:-./mass-actions.conf}"
doc[default_config]="Default config file. Here you can override variables or add additional commands to the array cmd_table[]."

additional_configs="${additional_configs:-/etc/mass-actions/*.conf $HOME/.mass-actions/*.conf}"
doc[additional_configs]="Blank-separated list of wildcarded additional config files. Here you can override variables or add additional commands to the array cmd_table[]."

status_dir="${status_dir:-./status-dir}"
doc[status_dir]="Output directory where progress logfiles of remotely issued ssh commands are created. You may grep in it."

# The rest is hardcoded here in case the config file does not exist

dry_run=${dry_run:-0}
doc[dry_run]="When enabled, remote ssh actions are only displayed instead of really executed."

verbose=${verbose:-0}
doc[verbose]="Increase speakyness."

confirm=${confirm:-0}
doc[confirm]="Each remote ssh command must be individually confirmed before it is actually executed. As a side effect, commands are running sequentially instead of parallel."

do_wait=${do_wait:-1}
allow_unknown_hosts=${allow_unknown_hosts:-0}
help=${help:-0}
status=${status:-0}
clean=${clean:-0}

sshopt="${sshopt:--4 -A -T -o StrictHostKeyChecking=no -o ForwardX11=no -o KbdInteractiveAuthentication=no -o VerifyHostKeyDNS=no -o ConnectTimeout=60 -o TCPKeepAlive=yes}"
max_jobs_parallelism="${max_jobs_parallelism:-3000}"

host_spec="${host_spec:-}"
action="${action:-}"
cmd="${cmd:-}"
prefix_cmd="${prefix_cmd:-set -o pipefail; shopt -s nullglob; }"

host_list="${host_list:-}"
host_filter="${host_filter:-}"

skip=${skip:-0}
max=${max:-0}

assoc_file="${assoc_file:-host-assoc.txt}"
assoc_dirs="${assoc_dirs:-. $HOME/.mass-actions /var/cache/mass-actions /etc/mass-actions}"

txt_ok="${txt_ok:-CMD OK}"
txt_fail="${txt_fail:-CMD FAIL \$?}"

# Command table for defining shorthand actions.
# Replace or extend this for your needs.
#
# Hint: use /etc/mass-actions/mass-actions.conf (or put it at another place)
# for overriding these example commands.
#
# All available action keywords can displayed by "$0 --help".
# Variables starting with tmp_ are suppressed in the display and may
# be used for internal structuring / better readability of complex commands.

declare -A cmd_table

cmd_table[test]="uptime"
cmd_table[mars_status]="if [[ -d /mars ]]; then marsadm view-replstate all; else echo 'NO_MARS_HOST'; fi"
cmd_table[drbd_status]="if [[ -r /proc/drbd ]]; then cat /proc/drbd; else echo 'NO_DRBD_HOST'; fi"
cmd_table[cm3_status]="cm3 -us || cm3 -s"
cmd_table[kernel_status]="uptime; ${cmd_table[cm3_status]}; ${cmd_table[mars_status]}; ${cmd_table[drbd_status]}; available=\"\$(ls -t /boot/vmlinuz-* | head -1 | cut -d- -f2-)\"; echo AVAILABLE_KERNEL=\$available; running=\"\$(cat /proc/version | awk '{print \$3; }')\"; echo RUNNING_KERNEL=\$running; if [[ \"\$running\" = \"\$available\" ]]; then echo KERNEL_IS_RECENT; elif [[ -r /proc/drbd ]] && grep ':Primary/' < /proc/drbd; then echo CANNOT_REBOOT_DRBD_PRIMARY; elif [[ -d /mars ]] && marsadm view-is-primary all | grep '^1\$'; then echo CANNOT_REBOOT_MARS_PRIMARY; elif [[ -x /usr/lib/1und1/scripts/is_node_in_mode_active.sh ]] && /usr/lib/1und1/scripts/is_node_in_mode_active.sh; then echo CANNOT_REBOOT_NODE_ACTIVE; else echo NEEDS_REBOOT; fi"
cmd_table[cm3_switchable_status]="if [[ -d /etc/ovz ]]; then cm3_switchable=1; else cm3_switchable=0; for dummy in {0..3}; do cm3 -us; slots_needed=\"\$(cm3 -s | grep \" \(remote\\|stopped\|broken\) \" | wc -l)\"; slots_available=\"\$(cm3 -s | grep idle | wc -l)\"; if (( slots_needed <= slots_available )); then cm3_switchable=1; break; fi; sleep 7; echo CM3_REPEAT; done; if (( cm3_switchable )); then echo CM3_SWITCHOVER_POSSIBLE; else echo CM3_SWITCHOVER_NOT_POSSIBLE; fi; fi"
cmd_table[mars_module_status]="uptime; mars_available=\"\$(modinfo mars | grep '^version' | awk '{ print \$2; }')\"; echo \"AVAILABLE_MARS=\$mars_available\"; mars_running=\"\$(cat /sys/module/mars/version | awk '{ print \$1; }')\"; echo \"RUNNING_MARS=\$mars_running\"; if [[ \"\$mars_running\" = \"\" ]]; then echo echo 'NO_MARS_HOST'; elif [[ \"\$mars_running\" = \"\$mars_available\" ]]; then echo MARS_IS_RECENT; elif marsadm view-is-primary all | grep '^1\$'; then echo MARS_CANNOT_RELOAD; else echo MARS_NEEDS_RELOAD; fi"
cmd_table[bgp_status]="if mountpoint /kunden/homepages/; then if ping -c 1 -w 10 8.8.8.8; then echo BGP_OK; else echo BGP_FAIL; fi; else echo BGP_UNUSED; fi"

cmd_table[detect_double]="if [[ -r /proc/drbd ]]; then cat /proc/drbd; if grep ' ds:' < /proc/drbd && mountpoint /mars && [[ -h /mars/uuid ]]; then marsadm view all; echo DOUBLE; else echo 'NO_MARS_HOST'; fi; else echo 'NO_DRBD_HOST'; fi"

cmd_table[kernel_reboot_when_necessary]="if { ${cmd_table[kernel_status]}; } | tee -a /dev/stderr | grep -q '^NEEDS_REBOOT$'; then if [[ -r /etc/lilo.conf ]] && grep rtrfix < /etc/lilo.conf; then lilo && sleep 3 && lilo -R rtrfix && sleep 3 && sync && echo coldreboot && coldreboot; else echo reboot; reboot; fi; fi"

cmd_table[mars_reload_when_necessary]="if { ${cmd_table[mars_module_status]}; } | tee -a /dev/stderr | grep -q '^MARS_NEEDS_RELOAD$'; then rmmod mars; modprobe mars; fi"

cmd_table[mars_switchover]="if [[ -d /mars ]]; then marsadm up all; marsadm primary all; fi; ${cmd_table[mars_status]}"
cmd_table[mars_failover]="if [[ -d /mars ]]; then marsadm pause-fetch all; marsadm attach all; marsadm primary --force all; fi; ${cmd_table[mars_status]}"

cmd_table[drbd_switchover]="if [[ -r /proc/drbd ]]; then drbdadm up all; drbdadm primary all; fi; ${cmd_table[drbd_status]}"
cmd_table[drbd_failover]="if [[ -r /proc/drbd ]]; then drbdadm disconnect all; drbdadm primary --force all; fi; ${cmd_table[drbd_status]}"

tmp_cm3_options="--timeout=3600 --vmhandler-timeout=3600"

tmp_mars_detect_others="export resources=\"\$(marsadm view-my-resources)\"; other_hosts=\"\"; for res in \$resources; do primary=\"\$(marsadm view-get-primary \$res)\"; if [[ \"\$primary\" != \"\$(hostname)\" ]] && ! [[ \"\$other_hosts\" =~ \$primary ]]; then other_hosts+=\" \$primary\"; fi; done"
tmp_mars_check_switchable="if ! [[ -d /proc/sys/mars ]]; then echo 'CANNOT_START_MARS_SWITCHOVER: kernel module not loaded'; exit -1; fi; if marsadm view-is-attach all | grep -q \"^0\$\"; then echo 'CANNOT_START_MARS_SWITCHOVER: some resource not attached'; exit -1; fi; if marsadm view-is-alive all | grep -v \"^---\" | grep -v \"^1\$\"; then echo 'CANNOT_START_MARS_SWITCHOVER: network is not alive'; exit -1; fi; if marsadm view-sync-rest all | grep -v \"^---\" | grep -v \"^0\$\"; then echo 'CANNOT_START_MARS_SWITCHOVER: some resource not synced'; exit -1; fi; if marsadm view-is-split-brain all | grep -v \"^---\" | grep -v \"^0\$\"; then echo 'CANNOT_START_MARS_SWITCHOVER: some resource is in split brain'; exit -1; fi; if marsadm view-is-consistent all | grep -v \"^---\" | grep -v \"^1\$\"; then echo 'CANNOT_START_MARS_SWITCHOVER: some resource is inconsistent'; exit -1; fi"
tmp_drbd_detect_others="export resources=\"\$(if [[ -d /etc/ovz/drbd.conf.d/ ]]; then  (cd /etc/ovz/drbd.conf.d/ && echo \$(ls ovz*.cfg ovz*.cfg.old | cut -d. -f1 | sort -u) ); else echo \$(cm3 --list-vms | cut -d. -f1); fi)\"; if grep -q ':Secondary/' < /proc/drbd; then other_hosts=\"\$(hostname | tr ab ba)\"; fi"
tmp_drbd_check_switchable="if grep \" cs:\" < /proc/drbd | grep -v \"cs:Connected .* ds:UpToDate/UpToDate\"; then echo 'CANNOT_START_DRBD_SWITCHOVER'; exit -1; fi"
tmp_cm3_stop_other="ssh $sshopt root@\$host \"$prefix_cmd cm3 $tmp_cm3_options --stop all; sleep 20; count=0; for i in \\\$(cm3 --list-vms --with-status | grep -i broken | cut -d: -f1 | cut -d. -f1); do echo \"RESTOPPING BROKEN \\\$i\"; (( count++ )); sleep 20; cm3 -us; sleep 10; cm3 $tmp_cm3_options --stop \\\$i; done\""
tmp_rebuild_ovz_tmp="for dev in /dev/vg*/ovz[0-9]*tmp; do if grep \"\$(echo \$dev | sed 's:^.*/::')\" < /proc/mounts; then echo \"Cannot rebuild \$dev\"; else echo \"Rebuild \$dev\"; if mkfs.xfs -f \$dev; then mount \$dev /mnt; chmod a+rwxt /mnt; umount /mnt; fi; fi; done"
#tmp_cm3_restart_local="for dummy in {0..2\}; do count=0; for i in \$(cm3 --list-vms --with-status | grep -i \"broken\|stopped\" | cut -d: -f1 | cut -d. -f1); do echo \"RESTARTING BROKEN \$i\"; (( count++ )); cm3 -us; sleep 10; cm3 $tmp_cm3_options --stop \$i; done; if (( count )); then sleep 10; cm3 $tmp_cm3_options --start all; sleep 10; fi; done"
tmp_cm3_restart_local="echo skip restart"
tmp_cm3_start_local="$tmp_rebuild_ovz_tmp; cm3 $tmp_cm3_options --start all; sleep 10; cm3 -us; $tmp_cm3_restart_local"
tmp_cm3_status_local="${cmd_table[mars_status]}; ${cmd_table[drbd_status]}; cm3 -us; cm3 -s | grep -q 'broken\|stopped' && exit -1"

tmp_mars_restart_cmd="drbdadm down all; /etc/init.d/drbd stop; sleep 3; /etc/init.d/drbd stop; sleep 3; rmmod drbd; sleep 1; modprobe mars"
# Problem: ssh evaluates its arguments once more. Solution: for symmetry reasons, use eval at the local side to get the same number of evaluations. Use enough backslashes to distinguish between the different numbers of evaluation levels.
tmp_mars_update_configs_resources_cmd="if which configure_InfongSpace.pl; then configure_InfongSpace.pl --update-infong \\\$res repltype=mars; elif which ui-config-modify; then ui-config-modify -c MARS_ENABLED=true; fi"
tmp_mars_make_resources_primary="echo RESOURCES \$resources; for res in \$resources; do echo marsadm create-resource \$res /dev/*/\$res; marsadm create-resource \\\$res /dev/*/\\\$res || exit -1; $tmp_mars_update_configs_resources_cmd; done"
tmp_mars_make_resources_secondary="echo RESOURCES \$resources; for res in \$resources; do echo marsadm join-resource \\\$res /dev/*/\\\$res; marsadm join-resource \\\$res /dev/*/\\\$res || exit -1; $tmp_mars_update_configs_resources_cmd; done"
tmp_update_configs_cmd="for i in /etc/ovz/drbd.conf.d/*.cfg; do mv \\\$i \\\$i.MARS; done; if [[ -r /etc/ovz/fstab.include ]]; then for file in /etc/ovz/fstab.include /etc/fstab; do sed --in-place=.MARS 's:\(/dev/drbd[0-9]\+\) \+/vz/\([0-9]\+\):/dev/mars/ovz\\2 /vz/\\2:' \\\$file; done; fi"
cmd_table[fix_mars_config]="eval \"$tmp_update_configs_cmd\""
tmp_restart_cm3_cmd="/etc/init.d/clustermanager stop; sleep 3; marsadm secondary all; /etc/init.d/clustermanager start; sleep 20"

tmp_mars_make_resources="if [[ -h /mars/uuid ]]; then $tmp_mars_restart_cmd; ssh $sshopt root@\$other_hosts \"$prefix_cmd $tmp_mars_restart_cmd\"; eval \"$tmp_mars_make_resources_primary\"; eval \"$tmp_update_configs_cmd\"; sleep 10; res=SCHEISSE; ssh $sshopt root@\$other_hosts \"$prefix_cmd $tmp_mars_make_resources_secondary; $tmp_update_configs_cmd\"; $tmp_restart_cm3_cmd; ssh $sshopt root@\$other_hosts \"$prefix_cmd $tmp_restart_cm3_cmd\"; fi"
tmp_mars_create_cluster="if ! [[ -h /mars/uuid ]]; then ssh $sshopt root@\$other_hosts \"mount /mars; marsadm create-cluster\"; marsadm join-cluster \$other_hosts; fi"
tmp_mars_migrate="mount /mars; if [[ \"\$other_hosts\" != \"\" ]] && [[ \"\$resources\" != \"\" ]] && [[ -r /proc/drbd ]] && grep ' ro:' < /proc/drbd && mountpoint /mars && ! grep 'ro:Primary/' < /proc/drbd && ! grep -o -i 'ds:[a-z/]\+' < /proc/drbd | grep -v 'UpToDate/UpToDate'; then echo \"---- MIGRATING \$(hostname) (\$other_hosts) [\$resources] ------\"; $tmp_mars_create_cluster; $tmp_mars_make_resources; fi"
#tmp_mars_migrate="echo WEGLASSEN"

cmd_table[cm3_get_resources]="if [[ -d  /sys/module/mars/ ]] ; then $tmp_mars_check_switchable; $tmp_mars_detect_others; elif [[ -r /proc/drbd ]]; then $tmp_drbd_check_switchable; $tmp_drbd_detect_others; else echo 'NO_CM3_RUNNING'; exit 0; fi; for res in \$resources; do echo \"\$res:\$(ls /dev/*/\$res | grep -v /mars | tail -1)\"; done"
cmd_table[cm3_switchover]="${cmd_table[cm3_get_resources]}; if [[ \"\$resources\" = \"\" ]]; then echo NO_RESOURCES_EXIST; exit 0; fi; echo \"other_hosts='\$other_hosts'\"; ${cmd_table[cm3_switchable_status]}; if (( !cm3_switchable )); then exit -1; fi; for host in \$other_hosts; do echo \"---- STOPPING \$host ------\"; $tmp_cm3_stop_other; sleep 10; done; $tmp_mars_migrate; echo \"---- STARTING \$(hostname) ------\"; sleep 10; $tmp_cm3_start_local; sleep 10; $tmp_cm3_status_local; ${cmd_table[bgp_status]}; exit 0"
cmd_table[repair_ovz_drbd]="/etc/init.d/drbd stop; /etc/init.d/clustermanager stop; /etc/init.d/drbd stop; rmmod mars; umount /mars; for i in /etc/ovz/drbd.conf.d/*.cfg.MARS /etc/ovz/fstab.include.MARS /etc/fstab.MARS; do mv \$i \${i/.MARS/}; done; /etc/init.d/drbd start; /etc/init.d/clustermanager start; mkfs.ext4 /dev/vg00/mars; mount /mars"

# The following functions may be overridden in the config file.
# When new functions are declared, their function names must follow
# the convention print_[a-z0-9_]+_status()
#
# Any new functions are automatically detected and included.
#
# Typically, they will grep in the output of previously defined remote commands
# and display some statistics about the contents.
#
# Important: these functions should not print anything when no data
# is available.

function print_ping_status
{
    local output="$(cat $status_dir/*.log |\
	grep -o " packets transmitted, [0-9]\+ received" |\
	awk '{ print $3; }' |\
	sort -n |\
	uniq -c |\
	awk '{ printf(" %s=%d", $2, $1); }')"
    if [[ "$output" != "" ]]; then
	echo "    PING STATUS:$output"
    fi
}

function print_ssh_status
{
    local msg_list="Host.key.verification.failed Permission.denied Connection.refused Connection.timed.out Could.not.resolve.hostname unknown.host"
    local output="$(cat $status_dir/*.log |\
	grep -o "\(${msg_list// /\\|}\)" |\
	sed 's/ /_/g' |\
	sort |\
	uniq -c |\
	awk '{ printf(" %s=%d", $2, $1); }')"
    if [[ "$output" != "" ]]; then
	echo "    SSH STATUS:$output"
    fi
}

function print_uptime_status
{
    local day_limits="0 1 7 30 365"
    local load_limits="0 1 3 10 30 100 300"
    local count=0
    local limit
    for limit in $day_limits; do
	eval local days_$limit=$(
	    cat $status_dir/*.log |\
		grep -o "up [0-9]\+ days," |\
		awk "{ if (\$2 >= $limit) { print \$2} }" |\
		wc -l)
	(( days_$limit && count++ ))
    done
    for limit in $load_limits; do
	eval local load_$limit=$(
	    cat $status_dir/*.log |\
		grep -o "load average: [0-9]\+" |\
		awk "{ if (\$3 >= $limit) { print \$3} }" |\
		wc -l)
	(( load_$limit && count++ ))
    done
    if (( count )); then
	echo -n "    UPTIME:"
	for limit in $day_limits; do
	    echo -n " >${limit}_days=$(eval echo "\${days_$limit}")"
	done
	echo ""
	echo -n "    LOADAVG:"
	for limit in $load_limits; do
	    echo -n " >${limit}=$(eval echo "\${load_$limit}")"
	done
	echo ""
    fi
}

function print_kernel_status
{
    local msg_list="KERNEL_IS_RECENT CANNOT_REBOOT[A-Z_]* NEEDS_REBOOT"
    local output="$(cat $status_dir/*.log |\
	grep -o "^\(${msg_list// /\\|}\)$" |\
	sort |\
	uniq -c |\
	awk '{ printf(" %s=%d", $2, $1); }')"
    if [[ "$output" != "" ]]; then
	echo "    KERNEL STATUS:$output"
    fi
}

function print_mars_status
{
    local msg_list="NO_MARS_HOST MARS_IS_RECENT MARS_CANNOT_RELOAD[A-Z_]* MARS_NEEDS_RELOAD"
    local output="$(cat $status_dir/*.log |\
	grep -o "^\(${msg_list// /\\|}\)$" |\
	sort |\
	uniq -c |\
	awk '{ printf(" %s=%d", $2, $1); }')"
    if [[ "$output" != "" ]]; then
	echo "    MARS STATUS:$output"
    fi

    local msg_list="ModuleNotLoaded UnResponsive NotJoined NotStarted EmergencyMode Replicating NotYetPrimary PausedSync Syncing PausedFetch PausedReplay NoPrimaryDesignated PrimaryUnreachable Replaying"
    local msg
    for msg in $msg_list; do
	eval "local $msg=0"
    done
    local count=0
    local var
    for var in $(cat $status_dir/*.log | grep -o "^\(${msg_list// /\\|}\)$"); do
	(( count++ ))
	eval "(( $var++ ))"
    done
    if (( count )); then
	echo -n "    MARS RESOURCES:"
	for msg in $msg_list; do
	    if (( $(eval echo \${$msg}) )); then
		echo -n " $msg=$(eval echo \${$msg})"
	    fi
	done
	echo ""
    fi
}

function print_drbd_status
{
    local output="$(cat $status_dir/*.log |\
	grep -i -o 'NO_DRBD_HOST\| cs:[a-z]\+\| ro:[a-z/]\+\| ds:[a-z/]\+' |\
	sed 's/^ *[a-z]\+://' |\
	sort |\
	uniq -c |\
	awk '{ printf(" %s=%d", $2, $1); }')"
    if [[ "$output" != "" ]]; then
	echo "    DRBD RESOURCES:$output"
    fi
}

function print_cm3_status
{
    local msg_list="NO_CM3_RUNNING NO_RESOURCES_EXIST CANNOT_START_DRBD_SWITCHOVER CANNOT_START_MARS_SWITCHOVER CM3_SWITCHOVER_POSSIBLE CM3_SWITCHOVER_NOT_POSSIBLE"
    local found=0
    local var;
    for var in $msg_list; do
	eval "local ${var//./_}=0";
    done
    local var
    for var in $(cat $status_dir/*.log | grep -o "^\(${msg_list// /\\|}\)" | sed 's/ /_/g'); do
	(( found++ ))
	eval "(( ${var//./_}++ ))"
    done
    if (( found )); then
	echo -n "    CM3 STATUS:"
	local msg
	for msg in $msg_list; do
	    if (( $(eval echo \${${msg//\./_}}) )); then
		echo -n " ${msg//\./_}=$(eval echo \${${msg//\./_}})"
	    fi
	done
	echo ""
    fi

    local key_list="started stopped active remote broken disabled"
    found=0
    local key
    for key in $key_list; do
	eval "local nr_$key=0"
    done
    for file in $status_dir/*.log; do
	# determine the last line, in case there are multiple invocations
	# of "cm3 -s" in the same logfile.
	line="$(grep -n "VM *.*STATE *NODE *STORAGE" < $file | tail -1 | cut -d: -f1)"
	if [[ "$line" != "" ]]; then
	    (( found++ ))
	    for key in $(tail -n +$line < $file | grep -o " \(${key_list// /\\|}\) .*" | awk '{ print $1; rest=$2; while (rest = gensub("[^,]*,?", "", "", rest)) { print $1; } }'); do
		eval "(( nr_$key++ ))"
	    done
	fi
    done
    if (( found )); then
	echo -n "    CM3 RESOURCES:"
	for key in $key_list; do
	    echo -n " $key=$(eval echo \${nr_$key})"
	done
	echo ""
    fi
}

function print_bgp_status
{
    local output="$(cat $status_dir/*.log |\
	grep '^\(BGP_[A-Z_]\+\)$' |\
	sort -r |\
	uniq -c |\
	awk '{ printf(" %s=%d", $2, $1); }')"
    if [[ "$output" != "" ]]; then
	echo "    BGP STATUS:$output"
    fi
}

# END of configuration variables and functions

param_vars="$(set | grep '^[_A-Za-z0-9]\+=' | cut -d= -f1 | grep -v "^tmp_")"

########################################################

# generic helper functions

function warn
{
    local txt="${1:-Unkown}"
    echo "WARNING: $txt" >> /dev/stderr
}

function fail
{
    local txt="${1:-Unkown failure}"
    echo "FAILURE: $txt" >> /dev/stderr
    rm -f /tmp/tmp_*.$$
    exit -1
}

function do_confirm
{
    local skip_this="$1"
    local active="${2:-$confirm}"
    local response

    (( !active )) && return 0

    [[ "$skip_this" != "" ]] && skip_this="S to skip, "
    echo -n "[CONFIRM: Press ${skip_this}Return to continue, ^C to abort] "
    read response
    ! [[ "$response" =~ ^[sS] ]]
    return $?
}

function remote
{
    local host="$1"
    local cmd="$2"
    local nofail="${3:-0}"

    (( verbose > 1 )) && echo "Executing on $host: '$cmd'" >> /dev/stderr
    [[ "${cmd## }" = "" ]] && return 0
    if ssh $sshopt root@$host "$cmd"; then
	return 0
    elif (( nofail )); then
	return $?
    else
	#fail "ssh to '$host' command '$cmd' failed with status $?"
	fail "ssh to '$host' command failed with status $?"
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

function source_when_possible
{
    local file="$1"
    local type="$2"

    if [[ -r "$file" ]]; then
	echo "Sourcing $type file '$file'"
	. "$file" || fail "$type file $file is not parsable"
    elif (( verbose )); then
	echo "Skipping non-existent $type file '$file'"
    fi
}

for i; do
    if [[ "$i" =~ ^--verbose ]]; then
	verbose=1
    fi
done

for file in $additional_configs; do
    source_when_possible "$file" "config"
done
source_when_possible "$default_config" "config"

# Allow forceful override of any _known_ variable at the command line
for i; do
    if [[ "$i" =~ ^--[-_A-Za-z0-9]+$ ]]; then
	param="${i#--}"
	var="${param//-/_}"
        [[ "$(eval "echo \"\${$var-UNSET}\"")" = "UNSET" ]] && fail "Variable '$var' is unknown"
	eval "$var=1"
    elif [[ "$i" =~ ^--[-_A-Za-z0-9]+= ]]; then
	param="${i#--}"
	var="${param%%=*}"
	var="${var//-/_}"
	val="${param#*=}"
        [[ "$(eval "echo \"\${$var-UNSET}\"")" = "UNSET" ]] && fail "Variable '$var' is unknown"
	eval "$var=$val"
    elif [[ "$i" =~ ^-h$ ]]; then
	help=1
    elif [[ "$i" =~ ^-v$ ]]; then
	(( verbose++ ))
    elif [[ "$host_spec" = "" ]]; then
	host_spec="$i"
    elif [[ "$action" = "" ]]; then
	action="$i"
    else
	fail "bad parameter syntax '$i'"
    fi
done

for dir in $assoc_dirs; do
    if [[ -r "$dir/$assoc_file" ]]; then
	assoc_file="$dir/$assoc_file"
	break
    fi
done

function do_help
{
cat <<EOF
usage: $0 [options] <host_spec> <action>

---------------------

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
	    doc_line="${doc[$i]}"
	    if [[ "$doc_line" != "" ]]; then
		echo -e "\t$doc_line"
	    fi
	fi
    done
)

---------------------

The following status functions are defined and are automatically called
upon $0 --status :

$(set | grep "^[a-z0-9_]\+ ()" | grep "^print_[a-z0-9_]\+_status")

---------------------

The following strings can be used for <host_spec>:
(see file $assoc_file)

$(cut -d: -f2 < $assoc_file | sort -u)

Hint: multiple specs may be separated by blanks, if you correctly
quote it to the shell. Example: $0 "host1 host7" "uptime"

Set operations can be performed by prefixing each spec or hostname with
"+" or "-" signs.

Example: $0 "+de.kae.bs -de.kae.bs;R08" "kernel_status"
will run on all hosts from complete datacenter "de.kae.bs" with the
exception of all hosts from Room 08.

Filtering: $0 --host-filter="store" "de.kae.bs" "kernel_status"
will only run on final target hostnames containing the substring "store".
You may also use bash regexes.

---------------------

The following pre-defined <action>s from cmd_table[] can be used (or,
give a full shell command in quotes):

$(
local i
for i in ${!cmd_table[*]}; do
    echo "$i"
done
)
EOF
}

if (( help )); then
    do_help
    exit 0
fi

function print_status
{
    local empty=0
    local failure=0
    local ok=0
    local working=0
    local file

    for file in $status_dir/*.log; do
	if ! [[ -s $file ]]; then
	    (( empty++ ))
	elif grep -q FAILURE $file; then
	    (( failure++ ))
	elif grep -q "^$txt_ok$" $file; then
	    (( ok++ ))
	else
	    (( working++ ))
	fi
    done
    echo "REMOTE SCRIPT STATUS: NotStarted=$empty Working=$working OK=$ok Fail=$failure"

    local func
    for func in $(set | grep "^[a-z0-9_]\+ ()" | grep -o "^print_[a-z0-9_]\+_status"); do
	$func
    done
}

if (( status )); then
    [[ -d "$status_dir" ]] || fail "Status directory '$status_dir' does not exist"
    sub_dir="$(ls $status_dir | grep "^run-" | sort | tail -1)"
    [[ -d "$status_dir/$sub_dir" ]] && export status_dir="$status_dir/$sub_dir"
    echo "Status from $status_dir:"
    print_status
    exit 0
fi

if (( clean )); then
    [[ -d "$status_dir" ]] || fail "Status directory '$status_dir' does not exist"
    echo "Are you sure to clean the status directory $status_dir/ including all its versioned subdirectories?"
    do_confirm 1 1
    rm -rf $status_dir
    exit 0
fi

# automatic versioning of status_dir 

export status_dir="$status_dir/run-$start_stamp"

########################################################

# compute host_list out of host_spec

function add_host
{
    local host="$1"
    local minus="$2"

    if (( minus )); then
	host_list="$(echo " $host_list " | sed "s/ $host / /g")"
    else
	host_list+=" $host"
    fi
}

function compute_host_list
{
    local host
    rm -f /tmp/tmp_*.$$
    local tmp1=/tmp/tmp_1.$$
    local tmp2=/tmp/tmp_2.$$

    [[ -r $assoc_file ]] || fail "cannot find assoc file '$assoc_file'"
    (( verbose )) && echo "Using assoc file '$assoc_file'"
    
    for host in $host_spec; do
	local minus=0
	if [[ "$host" =~ ^- ]]; then
	    host="${host/-/}"
	    minus=1
	else
	    host="${host/\+/}"
	fi
	host="${host//./\\.}"
	if grep -E ":$host\$" < $assoc_file > $tmp1; then
	    local i
	    for i in $(cut -d: -f1 < $tmp1); do
		add_host $i $minus
	    done
	elif grep -qE "^$host:" < $assoc_file; then
	    add_host $host $minus
	elif (( allow_unknown_hosts )); then
	    warn "host '$host' does not appear in $assoc_file"
	    add_host $host $minus
	else
	    fail "Keyword or hostname '$host' does not exist in $assoc_file"
	fi
    done
    rm -f /tmp/tmp_*.$$
    if [[ "$host_filter" != "" ]]; then
	local old_host_list="$host_list"
	host_list=""
	for host in $old_host_list; do
	    if [[ "$host" =~ $host_filter ]]; then
		host_list+=" $host"
	    fi
	done
    fi
    if (( skip > 0 )); then
	local old_host_list="$host_list"
	local count=0
	host_list=""
	for host in $old_host_list; do
	    (( ++count <= skip )) && continue
	    if [[ "$host" =~ $host_filter ]]; then
		host_list+=" $host"
	    fi
	done
    fi
    if (( max > 0 )); then
	local old_host_list="$host_list"
	local count=0
	host_list=""
	for host in $old_host_list; do
	    (( ++count > max )) && break
	    if [[ "$host" =~ $host_filter ]]; then
		host_list+=" $host"
	    fi
	done
    fi

    local host_count=$(echo ${host_list} | wc -w)
    if (( !host_count )); then
	fail "Resulting host list is empty - nothing can be done at all"
    fi
    if (( verbose )); then
	echo "USING FINAL host_list: ${host_list}"
    else
	echo "Will run on $host_count hosts"
    fi
}

function get_cmd
{
    if [[ "$cmd" = "" ]]; then
	if [[ "$action" = "ping" ]]; then
	    echo "Running a pure ping to $(echo "$host_list" | wc -w) hosts"
	    cmd="ping"
	elif [[ "${cmd_table[$action]}" != "" ]]; then
	    echo "Using predefined cmd_table[] action '$action'"
	    if ! [[ "$action" =~ _status ]]; then
		do_confirm 1 1
	    fi
	    cmd="$prefix_cmd${cmd_table[$action]}"
	elif [[ "$action" != "" ]]; then
	    echo ""
	    echo "Running action '$action' as a command on $(echo "$host_list" | wc -w) hosts"
	    do_confirm 1 1
	    cmd="$action"
	else
	    fail "No action given."
	fi
    else
	echo ""
	echo "Using given command '$cmd' on $(echo "$host_list" | wc -w) hosts"
	do_confirm 1 1
    fi
}

########################################################

# main program

function main
{
    mkdir -p $status_dir || fail "connot create status directory '$status_dir'"

    script_start=$(date +%s)

    if (( confirm )); then
	echo "CONFIRM mode: everything is running SEQUENTIALLY"
    else
	echo "START forking sub-processes"
    fi
    local host
    for host in $host_list; do
	if (( confirm )); then
	    if remote_action $host "$cmd" 2>&1; then
		eval echo "$txt_ok"
	    else
		eval echo "$txt_fail"
	    fi 2>&1 | tee $status_dir/$host.log
	else
	    if (( dry_run )); then
		echo "DRY_RUN REMOTE $host ACTION '$cmd'"
		eval echo "$txt_ok"
	    elif [[ "$cmd" = "ping" ]]; then
		ping -c 1 -w 10 $host
		eval echo "$txt_ok"
	    elif remote $host "$cmd" 2>&1 ; then
		eval echo "$txt_ok"
	    else
		eval echo "$txt_fail"
	    fi > $status_dir/$host.log 2>&1 &
	    while (( $(jobs | wc -l) > max_jobs_parallelism )); do
		sleep 1
	    done
	fi
    done
    (( !confirm )) && echo "DONE  forking sub-processes"
    if (( do_wait )); then
	echo "Waiting for termination of sub-processes"
	local duration=1
	while (( $( pstree $$ | wc -l ) > 2 )); do
	    print_status
	    sleep $duration
	    (( duration < 10 && duration++ ))
	done
	wait
    fi

    script_end=$(date +%s)
    echo "ESTIMATED script duration: $(( script_end - script_start )) seconds"
    print_status
}

compute_host_list
get_cmd
main
exit 0
