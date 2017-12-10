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

############################################################

# TST summer 2017 lab prototype

# Generic MARS background migration of a VM / container.
# Plugins can be used for adaptation to system-specific sub-operations
# (e.g. the 1&1-specific clustermanager cm3)

# There are some basic conventions / assumptions:
#   - MARS resource names are equal to LV names and to KVM / LXC names
#   - All hosts are in DNS with their pure names (accessible via resolv.conf)
#   - There is a 1:n relationship between each
#        $storage_host : $hypervisor_host : $container_host

set -o pipefail
shopt -s nullglob
export LC_ALL=C
export start_stamp="$(date "+%F_%T" | sed 's/:/./g')"

# parameters
operation="${operation:-}"
res="${res:-}"
target_primary="${target_primary:-}"
target_secondary="${target_secondary:-}"
target_percent=${target_percent:-85}

# short options
dry_run=${dry_run:-0}
verbose=${verbose:-0}
confirm=${confirm:-1}
force=${force:-0}
logdir="${logdir:-.}"
min_space="${min_space:-20000000}"

# more complex options
ssh_opt="${ssh_opt:--4 -A -o StrictHostKeyChecking=no -o ForwardX11=no -o KbdInteractiveAuthentication=no -o VerifyHostKeyDNS=no}"
rsync_opt="${rsync_opt:- -aSH --info=STATS}"
rsync_opt_prepare="${rsync_opt_prepare:---exclude='.filemon2' --delete}"
rsync_opt_hot="${rsync_opt_hot:---delete}"
rsync_nice="${rsync_nice:-nice -19}"
rsync_repeat_prepare="${rsync_repeat_prepare:-5}"
rsync_repeat_hot="${rsync_repeat_hot:-3}"

lvremove_opt="${lvremove_opt:--f}"

# some constants
tmp_suffix="${tmp_suffix:--tmp}"
shrink_suffix_old="${shrink_suffix_old:--preshrink}"
commands_needed="${commands_needed:-ssh rsync grep sed awk sort head tail tee cat ls cut ping date mkdir rm bc}"

######################################################################

# help

function helpme
{
    cat <<EOF
Usage:
  $0 --help
     Show help
  $0 --variable=<value>
     Override any shell variable

Actions for resource migration:

  $0 migrate_prepare <resource> <target_primary> [<target_secondary>]
     Allocate LVM space at the targets and start MARS replication.

  $0 migrate_wait    <resource> <target_primary> [<target_secondary>]
     Wait until MARS replication reports UpToDate.

  $0 migrate_finish  <resource> <target_primary> [<target_secondary>]
     Call hooks for handover to the targets.

  $0 migrate         <resource> <target_primary> [<target_secondary>]
     Run the sequence migrate_prepare ; migrate_wait ; migrate_finish.

  $0 migrate_cleanup <resource>
     Remove old / currently unused LV replicas from MARS and deallocate from LVM.

  $0 manual_migrate_config  <resource> <target_primary> [<target_secondary>]
     Transfer only the cluster config, without changing the MARS replicas.
     This does no resource stopping / restarting.
     Useful for reverting a failed migration.

  $0 manual_config_update <hostname>
     Only update the cluster config, without changing anything else.
     Useful for manual repair of failed migration.


Actions for inplace FS shrinking:

  $0 shrink_prepare  <resource> [<percent>]
     Allocate temporary LVM space (when possible) and create initial raw FS copy.
     Default percent value(when left out) is $target_percent.

  $0 shrink_finish   <resource>
     Incrementally update the FS copy, swap old <=> new copy with small downtime.

  $0 shrink_cleanup  <resource>
     Remove old FS copy from LVM.

  $0 shrink          <resource> <percent>
     Run the sequence shrink_prepare ; shrink_finish ; shrink_cleanup.

Actions for inplace FS extension:

  $0 extend          <resource> <percent>

Global maintenance:

  $0 lv_cleanup      <resource>

General features:

  - instead of <percent>, an absolute amount of storage with suffix
    'k' or 'm' or 'g' can be given.

  - when <resource> is currently stopped, login to the container is
    not possible, and in turn the hypervisor node and primary storage node
    cannot be automatically determined. In such a case, the missing
    nodes can be specified via the syntax
        <resource>:<hypervisor>:<primary_storage>

  - the following LV suffixes are used (naming convention):
    $tmp_suffix = currently emerging version for shrinking
    $shrink_suffix_old = old version before shrinking took place
EOF
   source_hooks
   verbose=0 call_hook hook_describe_plugin
}

######################################################################

# basic infrastructure

function fail
{
    local txt="${1:-Unkown failure}"
    echo "FAILURE: $txt" >> /dev/stderr
    exit -1
}

# Unfortunately, the bash has no primitive for running an arbitrary
# (complex) command until some timeout is exceeded.
#
# Workaround by disjoint waiting for an additional background sleep process.
#
function timeout_cmd
{
    local cmd="$1"
    local limit="${2:-30}"
    local do_fail="${3:-0}"

    if (( limit <= 0 )); then # timeout is disabled
        bash -c "$cmd"
        local rc=$?
        #echo "RC=$rc" >> /dev/stderr
        return $rc
    fi

    set +m
    eval "$cmd" &
    local cmd_pid=$!

    sleep $limit &
    local sleep_pid=$!

    # disjoint waiting
    wait -n $cmd_pid $sleep_pid
    local rc1=$?
    #echo "RC1=$rc1" >> /dev/stderr

    kill $sleep_pid > /dev/null 2>&1
    kill $cmd_pid > /dev/null 2>&1
    wait $cmd_pid > /dev/null 2>&1
    local rc2=$?
    #echo "RC2=$rc2" >> /dev/stderr

    # ensure to eat the background status, +m alone is not enough
    wait $sleep_pid > /dev/null 2>&1

    if (( rc2 == 143 )); then
	if (( do_fail )); then
	    fail "TIMEOUT $limit seconds for '$cmd' reached"
	else
	    echo "TIMEOUT $limit seconds for '$cmd' reached" >> /dev/stderr
	fi
    fi

    local rc=$(( rc1 | rc2 ))
    #echo "RC=$rc" >> /dev/stderr
    return $rc
}

function source_hooks
{
    local dir
    local path

    declare -g -A sourced_hook
    for dir in /etc/mars/hooks ./hooks .; do
	for path in $dir/hooks-*.sh; do
	    [[ "${sourced_hook[$path]}" != "" ]] && continue
	    echo "Sourcing hooks in '$path'"
	    source $path || fail "cannot source '$path'"
	    sourced_hook[$path]=1
	done
    done
}

args_info=""

function scan_args
{
    local -a params
    local index=0
    local par
    for par in "$@"; do
	if [[ "$par" = "--help" ]]; then
	    helpme
	    exit 0
	elif [[ "$par" =~ "=" ]]; then
	    par="${par#--}"
	    local lhs="$(echo "$par" | cut -d= -f1)"
	    local rhs="$(echo "$par" | cut -d= -f2-)"
	    lhs="${lhs//-/_}"
	    echo "$lhs=$rhs"
	    eval "$lhs=$rhs"
	    continue
	elif [[ ":$par" =~ ":--" ]]; then
	    par="${par#--}"
	    par="${par//-/_}"
	    echo "$par=1"
	    eval "$par=1"
	    continue
	fi
	if (( !index )); then
	    if [[ "$par" =~ migrate_cleanup|lv_cleanup ]]; then
		local -a params=(operation res)	
	    elif [[ "$par" =~ shrink|extend ]]; then
		local -a params=(operation res target_percent)
	    elif [[ "$par" =~ migrate ]]; then
		local -a params=(operation res target_primary target_secondary)
	    elif [[ "$par" =~ manual_config_update ]]; then
		local -a params=(operation host)
	    else
		helpme
		fail "unknown operation '$1'"
	    fi
	fi
	local lhs="${params[index]}"
	if [[ "$lhs" != "" ]]; then
	    echo "$lhs=$par"
	    eval "$lhs=$par"
	    args_info+=".${par//:/_}"
	    (( index++ ))
	else
	    helpme
	    fail "stray parameter '$par'"
	fi
    done
}

function do_confirm
{
    local skip="$1"
    local response

    (( !confirm )) && return 0

    [[ "$skip" != "" ]] && skip="S to skip, "
    echo -n "[CONFIRM: Press ${skip}Return to continue, ^C to abort] "
    read -e response
    ! [[ "$response" =~ ^[sS] ]]
    return $?
}

function remote
{
    local host="$1"
    local cmd="$2"
    local nofail="${3:-0}"

    (( verbose > 0 )) && echo "Executing on $host: '$cmd'" >> /dev/stderr
    [[ "$host" = "" ]] && return
    [[ "${cmd## }" = "" ]] && return
    ssh $ssh_opt "root@$host" "$cmd"
    local rc=$?
    if (( !rc )); then
	return 0
    elif (( nofail )); then
	return $rc
    else
	fail "ssh to '$host' command '$cmd' failed with status $rc"
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

function log
{
    local dir="$1"
    local file="$2"

    if [[ "$dir" != "" ]] && [[ "$file" != "" ]]; then
	tee -a "$dir/$file"
    else
	cat
    fi
}

section_nr=1

function section
{
    local txt="${1:--}"
    echo ""
    echo "==================================================================="
    echo "$(( section_nr++ )). $txt"
    echo ""
}

function commands_installed
{
    local cmd_list="$1"

    local cmd
    for cmd in $cmd_list; do
	if ! which $cmd; then
	    fail "shell command '$cmd' is not installed"
	fi
    done
}

function exists_hook
{
    local name="$1"
    [[ "$(type -t $name)" =~ function ]]
}

function call_hook
{
    local name="$1"
    if exists_hook "$name"; then
	(( verbose )) && echo "Running hook: $name $@" >> /dev/stderr
	shift
	$name "$@" || fail "cannot execute hook function '$name'"
    else
	echo "Skipping undefined hook '$name'"  >> /dev/stderr
    fi
}

######################################################################

# helper functions for determining hosts / relationships

declare -A hypervisor_host

function get_hyper
{
    local res="$1"

    declare -g hypervisor_host
    local hyper="${hypervisor_host[$res]}"
    if [[ "$hyper" = "" ]]; then
	hyper="$(call_hook hook_get_hyper "$res")" ||\
	    fail "Cannot determine hypervisor hostname for resource '$res'"
	hypervisor_host[$res]="$hyper"
    fi
    [[ "$hyper" = "" ]] && return -1
    echo "$hyper"
}

declare -A storage_host

function get_store
{
    local res="$1"

    declare -g storage_host
    local store="${storage_host[$res]}"
    if [[ "$store" = "" ]]; then
	store="$(call_hook hook_get_store "$res")" ||\
	    fail "Cannot determine storage hostname for resource '$res'"
	if [[ "$store" = "" ]]; then
	    # assume local storage
	    store="$(get_hyper "$res")"
	fi
	storage_host[$res]="$store"
    fi
    [[ "$store" = "" ]] && return -1
    echo "$store"
}

declare -A vgs

function get_vg
{
    local host="$1"

    declare -g vgs
    local vg="${vgs[$host]}"
    if [[ "$vg" = "" ]]; then
	vg="$(call_hook hook_get_vg "$host")" ||\
	    fail "Cannot determine volume group for host '$host'"
	vgs[$host]="$vg"
    fi
    [[ "$vg" = "" ]] && return -1
    echo "$vg"
}

######################################################################

# LV cleanup over the whole pool (may take some time)

function LV_cleanup
{
    local primary="$1"
    local lv_name="$2"
    local do_it="${3:-0}"

    local total_count=0
    local remove_count=0
    section "Determine hosts and LVs for cleanup"

    local to_check="$(remote "$primary" "marsadm view-cluster-members")"
    echo "Determined the following cluster members: " $to_check >> /dev/stderr

    section "Run over the host list for cleanup"

    echo "do_remove:host:LV_path"
    local host
    for host in $to_check; do
	local path
	for path in $(remote "$host" "ls /dev/*/$lv_name*" 2>/dev/null | grep -v "/mars/" ); do
	    local do_remove=0
	    local disk="$(remote "$host" "marsadm view-get-disk $lv_name")" 2>/dev/null
	    if [[ "$disk" = "" ]]; then
		do_remove=1
		(( remove_count++ ))
	    fi
	    echo "$do_remove:$host:$path"
	    (( total_count++ ))
	    if (( do_remove && do_it )); then
		call_hook hook_disconnect "$host" "$lv_name"
		remote "$host" "lvremove $lvremove_opt $path"
	    fi
	done
    done
    echo "---------------"
    echo "Total number of LVs:    $total_count"
    echo "Total number to remove: $remove_count"
    if (( !do_it && !total )); then
	echo "Nothing to do. Exiting."
	exit 0
    fi
}

######################################################################

# checks for LV migration

function check_migration
{
    # works on global parameters
    [[ "$target_primary" = "" ]] && fail "target hostname is not defined"
    [[ "$target_primary" = "$primary" ]] && fail "target host '$target_primary' needs to be distinct from source host"
    for host in $target_primary $target_secondary; do
	ping -c 1 "$host" > /dev/null || fail "Host '$host' is not pingable"
	remote "$host" "mountpoint /mars > /dev/null"
	remote "$host" "[[ -d /mars/ips/ ]]"
    done
    call_hook hook_check_host "$primary $secondary_list $target_primary $target_secondary"
}

function check_vg_space
{
    local host="$1"
    local min_size="$2"

    [[ "$host" = "" ]] && return

    local vg_name="$(get_vg "$host")" || fail "cannot determine VG for host '$host'"
    local rest="$(remote "$host" "vgs --noheadings -o \"vg_free\" --units k $vg_name" | sed 's/\.[0-9]\+//' | sed 's/k//')" || fail "cannot determine VG rest space"
    echo "$vg_name REST space on '$host' : $rest"
    if (( rest <= min_size )); then
	fail "NOT ENOUGH SPACE on $host (needed: $min_size)"
    fi
}

######################################################################

# actions for LV migration

function get_stripe_extra
{
    # compute LVM stripe number
    local stripes="$(remote "$host" "vgs" | grep '$vg_name ' | awk '{ print $2; }')"
    local extra=""
    if (( stripes > 1 )); then
	echo "Using $stripes LVM stripes" >> /dev/stderr
	extra="-i $stripes"
    fi
    echo "$extra"
}

function create_migration_space
{
    local host="$1"
    local lv_name="$2"
    local size="$3"

    # some checks
    [[ "$host" = "" ]] && return
    local vg_name="$(get_vg "$host")" || fail "cannot determine VG for host '$host'"
    remote "$host" "if [[ -e /dev/$vg_name/${lv_name} ]]; then echo \"REFUSING to overwrite /dev/$vg_name/${lv_name} on $host - Do this by hand\"; exit -1; fi"
    local extra="$(get_stripe_extra "$host" "$vg_name")"

    # do it
    remote "$host" "lvcreate -L ${size}k $etxra -n $lv_name $vg_name"
}

function migration_prepare
{
    local source_primary="$1"
    local lv_name="$2"
    local target_primary="$3"
    local target_secondary="$4"

    section "Ensure that \"marsadm merge-cluster\" has been executed."

    # This is idempotent.
    if exists_hook hook_merge_cluster; then
	call_hook hook_merge_cluster "$source_primary" "$target_primary"
	call_hook hook_merge_cluster "$source_primary" "$target_secondary"
    else
	remote "$target_primary" "marsadm merge-cluster $source_primary"
	remote "$target_secondary" "marsadm merge-cluster $source_primary"
    fi

    remote "$target_primary" "marsadm wait-cluster"

    section "Idempotence: check whether the additional replica has been alread created"

    local already_present="$(remote "$target_primary" "marsadm view-is-attach $lv_name")"
    if (( already_present )); then
	echo "Nothing to do: resource '$lv_name' is already present at '$target_primary'"
	return
    fi

    section "Re-determine and check all resource sizes for safety"

    local size="$(( $(remote "$source_primary" "marsadm view-sync-size $lv_name") / 1024 ))" ||\
	fail "cannot determine resource size"

    check_vg_space "$target_primary" "$size"
    check_vg_space "$target_secondary" "$size"

    local primary_vg_name="$(get_vg "$target_primary")"
    local secondary_vg_name="$(get_vg "$target_secondary")"
    local primary_dev="/dev/$primary_vg_name/${lv_name}"
    local secondary_dev="/dev/$secondary_vg_name/${lv_name}"

    section "Create migration spaces"

    create_migration_space "$target_primary" "$lv_name" "$size"
    create_migration_space "$target_secondary" "$lv_name" "$size"

    section "Join the resources"

    if exists_hook hook_join_resource; then
	call_hook hook_join_resource "$source_primary" "$target_primary" "$lv_name" "$primary_dev"
	call_hook hook_join_resource "$source_primary" "$target_secondary" "$lv_name" "$secondary_dev"
    else
	remote "$target_primary" "marsadm join-resource $lv_name $primary_dev"
	remote "$target_secondary" "marsadm join-resource $lv_name $secondary_dev"
    fi
    remote "$target_primary" "marsadm wait-cluster"
}

function wait_resource_uptodate
{
    local host_list="$1"
    local res="$2"

    section "Wait for MARS UpToDate"

    local host
    for host in $host_list; do
	remote "$host" "marsadm wait-cluster"
    done
    (( verbose )) && echo "$(date) sync rests for '$host_list':"
    local max_wait=15
    while true; do
	(( verbose )) && echo -n "$(date) sync rests:"
	local syncing=0
	local total_rest=0
	for host in $host_list; do
	    local rest="$(verbose=0 remote "$host" "marsadm view-sync-rest $res")"
	    if (( verbose )); then
		if (( rest < 1024 )); then
		    echo -n " $(( rest ))B"
		elif (( rest < 1024 * 1024 )); then
		    echo -n " $(( rest / 1024 ))KiB"
		elif (( rest < 1024 * 1024 * 1024 )); then
		    echo -n " $(( rest / 1024 / 1024 ))MiB"
		else
		    echo -n " $(( rest / 1024 / 1024 / 1024 ))GiB"
		fi
	    fi
	    if (( rest > 0 )); then
		(( syncing++ ))
	    else
		local status="$(verbose=0 remote "$host" "marsadm view-diskstate $res")"
		(( verbose )) && echo -n "/$status"
		if ! [[ "$status" =~ UpToDate ]]; then
		    (( syncing++ ))
		fi
	    fi
	    (( total_rest += rest ))
	done
	(( verbose )) && echo ""
	(( !syncing )) && break
	if (( total_rest > 0 )); then
	    sleep 60
	else
	    (( max_wait-- < 0 )) && break
	    sleep 1
	fi
    done
    (( verbose )) && echo "$(date) sync appears to have finished at '$host_list'"
}

function migrate_resource
{
    local source_primary="$1"
    local target_primary="$2"
    local target_secondary="$3"
    local res="$4"

    wait_resource_uptodate "$target_primary" "$res"

    # critical path
    section "Stopping old primary"

    call_hook hook_resource_stop "$source_primary" "$res"

    section "Migrate cluster config"

    call_hook hook_migrate_cm3_config "$source_primary" "$target_primary" "$res"

    section "Starting new primary"

    call_hook hook_resource_start "$target_primary" "$res"

    section "Checking new primary"

    call_hook hook_resource_check "$res"
}

function migrate_cleanup
{
    local host_list="$1"
    local host_list2="$2"
    local res="$3"

    section "Cleanup migration data at $host_list"

    local host
    for host in $host_list; do
	local vg_name="$(get_vg "$host")"
	if [[ "$vg_name" != "" ]]; then
	    remote "$host" "marsadm wait-cluster || echo IGNORE cleanup"
	    remote "$host" "marsadm down $res || echo IGNORE cleanup"
	    remote "$host" "marsadm leave-resource $res || marsadm leave-resource --force $res || echo IGNORE cleanup"
	    remote "$host" "lvremove $lvremove_opt /dev/$vg_name/$res$tmp_suffix || echo IGNORE cleanup"
	    remote "$host" "lvremove $lvremove_opt /dev/$vg_name/$res-copy || echo IGNORE cleanup"
	    remote "$host" "lvremove $lvremove_opt /dev/$vg_name/$res$shrink_suffix_old || echo IGNORE cleanup"
	    remote "$host" "lvremove $lvremove_opt /dev/$vg_name/$res || echo IGNORE cleanup"
	    sleep 3
	fi
    done

    section "Recompute host list"

    local new_host_list="$(echo $(
	for host in $host_list $host_list2; do
	    echo "$host"
	    remote "$host" "marsadm lowlevel-ls-host-ips" 2>/dev/null
	done |\
	    awk '{ print $1; }' |\
	    sort -u ))"
    echo "Augmented host list: $new_host_list"
    host_list="$new_host_list"

    for host in $host_list; do
	remote "$host" "marsadm wait-cluster || echo IGNORE cleanup"
    done

    section "Split cluster at $host_list"

    sleep 10
    call_hook hook_prepare_hosts "$host_list"
    call_hook hook_split_cluster "$host_list"
    call_hook hook_finish_hosts "$host_list"
}

######################################################################

# checks for FS shrinking

function determine_space
{
    # works on global variables
    lv_path="$(remote "$primary" "lvs --noheadings --separator ':' -o \"vg_name,lv_name\"" | grep ":$res$" | sed 's/ //g' | awk -F':' '{ printf("/dev/%s/%s", $1, $2); }')" || fail "cannot determine lv_path"

    vg_name="$(echo "$lv_path" | cut -d/ -f3)" || fail "cannot determine vg_name"

    echo "Determined the following VG name: \"$vg_name\""
    echo "Determined the following LV path: \"$lv_path\""

    local dev="/dev/$vg_name/$lv_name"
    remote "$primary" "if [[ -e ${dev}$shrink_suffix_old ]]; then echo \"REFUSING to overwrite ${dev}$shrink_suffix_old on $primary - First remove it - Do this by hand\"; exit -1; fi"

    df="$(remote "$hyper" "df $mnt" | grep "/dev/")" || fail "cannot determine df data"
    used_space="$(echo "$df" | awk '{print $3;}')"
    total_space="$(echo "$df" | awk '{print $2;}')"
    # absolute or relative space computation
    case "$target_percent" in
    *k)
	target_space="${target_percent%k}"
	;;
    *m)
	target_space="$(( ${target_percent%m} * 1024 ))"
	;;
    *g)
	target_space="$(( ${target_percent%g} * 1024 * 1024 ))"
	;;
    *)
	target_space="${target_space:-$(( used_space * 100 / target_percent + 1 ))}" || fail "cannot compute target_space"
	;;
    esac
    (( target_space < min_space )) && target_space=$min_space

    echo "Determined USED  space: $used_space"
    echo "Determined TOTAL space: $total_space"
    echo "Computed TARGET  space: $target_space"
}

function check_shrinking
{
    # works on global variables
    if (( target_space >= total_space )); then
	echo "No need for shrinking the LV space of $res"
	(( !force )) && exit 0
    fi
    for host in $primary $secondary_list; do
	check_vg_space "$host" "$target_space"
    done
}

function check_extending
{
    # works on global variables
    if (( target_space <= total_space )); then
	echo "No need for extending the LV space of $res"
	(( !force )) && exit 0
    fi
    delta_space="$(( target_space - total_space + 1024 ))"
    echo "Computed DELTA   space: $delta_space"
    for host in $primary $secondary_list; do
	check_vg_space "$host" "$delta_space"
    done
}

######################################################################

# actions for FS shrinking

optimize_dentry_cache="${optimize_dentry_cache:-1}"

mkfs_cmd="${mkfs_cmd:-mkfs.xfs -s size=4096 -d agcount=1024}"
mount_opts="${mount_opts:--o rw,nosuid,noatime,attr2,inode64,usrquota}"
reuse_mount="${reuse_mount:-1}"
reuse_lv="${reuse_lv:-1}"
do_quota="${do_quota:-2}" # 1 = global xfs quota transfer, 2 = additionally local one
xfs_dump_dir="${xfs_dump_dir:-xfs-quota-$start_stamp}"
xfs_quota_enable="${xfs_quota_enable:-xfs_quota -x -c enable}"
xfs_dump="${xfs_dump:-xfs_quota -x -c dump}"
xfs_restore="${xfs_restore:-xfs_quota -x -c restore}"

function transfer_quota
{
    local hyper="$1"
    local lv_name="$2"
    local mnt1="$3" # needs to be already mounted
    local mnt2="$4" # needs to be already mounted

    (( !do_quota )) && return

    section "Checks for xfs quota transfer"

    remote "$hyper" "mountpoint $mnt1 && mountpoint $mnt2"

    section "Transfer xfs quota"

    mkdir -p "$xfs_dump_dir"
    local dumpfile="$xfs_dump_dir/xfs_dump.global.$hyper.$lv_name"

    # enable quota
    remote "$hyper" "$xfs_quota_enable $m2"

    # transfer quota
    remote "$hyper" "$xfs_dump $mnt1" > $dumpfile
    ls -l $dumpfile
    wc -l $dumpfile
    if [[ -s $dumpfile ]]; then
	local dev_name="$(remote "$hyper" "df $mnt2" | grep /dev/ | awk '{ print $1; }')"
	echo "dev_name=$dev_name"
	{
	    echo "fs = $dev_name"
	    tail -n +2 < $dumpfile
	} > $dumpfile.new
	remote "$hyper" "$xfs_restore $mnt2" < $dumpfile.new
    else
	echo "QUOTA IS EMPTY"
    fi
}

function create_shrink_space
{
    local host="$1"
    local lv_name="$2"
    local size="$3"

    # some checks
    section "Checking shrink space on $host"

    local vg_name="$(get_vg "$host")" || fail "cannot determine VG for host '$host'"
    remote "$host" "if [[ -e /dev/$vg_name/${lv_name}$shrink_suffix_old ]]; then echo \"REFUSING to overwrite /dev/$vg_name/${lv_name}$shrink_suffix_old on $host - Do this by hand\"; exit -1; fi"
    if (( reuse_lv )); then
	# check whether LV already exists
	if remote "$host" "[[ -e /dev/$vg_name/${lv_name}$tmp_suffix ]]" 1; then
	    echo "reusing already exists LV /dev/$vg_name/${lv_name}$tmp_suffix on '$host'"
	    return
	fi
    fi
    call_hook hook_disconnect "$host" "$lv_name"
    remote "$host" "if [[ -e /dev/$vg_name/${lv_name}$tmp_suffix ]]; then lvremove $lvremove_opt /dev/$vg_name/${lv_name}$tmp_suffix; fi"

    # do it
    section "Creating shrink space on $host"

    local extra="$(get_stripe_extra "$host" "$vg_name")"
    remote "$host" "lvcreate -L ${size}k $extra -n ${lv_name}$tmp_suffix $vg_name"
    remote "$host" "$mkfs_cmd /dev/$vg_name/${lv_name}$tmp_suffix"
}

function create_shrink_space_all
{
    local host_list="$1"
    local lv_name="$2"
    local size="$3"

    local host
    for host in $host_list; do
	create_shrink_space "$host" "$lv_name" "$size" "$count"
    done
}

# convention: add a suffix -tmp to the device and mountpoint names each

function make_tmp_mount
{
    local hyper="$1"
    local store="$2"
    local lv_name="$3"
    local suffix="${4:-$tmp_suffix}"

    local mnt="$(call_hook hook_get_mountpoint "$lv_name")"
    if (( reuse_mount )); then
	section "Checking mount $mnt$suffix at $hyper"
	if remote "$hyper" "mountpoint $mnt$suffix" 1; then
	    echo "Reusing already existing mount $mnt$suffix on $hyper"
	    return
	fi
    fi

    section "Creating mount $mnt$suffix at $hyper"

    local vg_name="$(get_vg "$store")" || fail "cannot determine VG for host '$store'"
    local dev_tmp="/dev/$vg_name/$lv_name$suffix"
    if [[ "$store" != "$hyper" ]]; then
	# create remote devices instead
	local old_dev="$dev_tmp"
	dev_tmp="$(call_hook hook_connect "$store" "$hyper" "$lv_name$suffix" 2>&1 | tee /dev/stderr | grep "^NEW_DEV" | cut -d: -f2)"
	echo "using tmp dev '$dev_tmp'"
	[[ "$dev_tmp" = "" ]] && fail "cannot setup remote device between hosts '$store' => '$hyper'"
    fi
    remote "$hyper" "mkdir -p $mnt$suffix"
    remote "$hyper" "mount $mount_opts $dev_tmp $mnt$suffix"
}

function make_tmp_umount
{
    local hyper="$1"
    local store="$2"
    local lv_name="$3"
    local suffix="${4:-$tmp_suffix}"

    section "Removing temporary mount from $hyper"

    remote "$hyper" "if mountpoint $mnt$suffix/; then sync; umount $mnt$suffix/ || umount -f $mnt$suffix/; fi"

    if [[ "$store" != "$hyper" ]]; then
	sleep 1
	call_hook hook_disconnect "$store" "$lv_name$suffix"
    fi
}

function copy_data
{
    local hyper="$1"
    local lv_name="$2"
    local suffix="${3:-$tmp_suffix}"
    local nice="${4:-$rsync_nice}"
    local add_opt="${5:-$rsync_opt_prepare}"
    local repeat_count="${6:-$rsync_repeat_prepare}"

    local time_cmd="/usr/bin/time -f 'rss=%M elapsed=%e'"

    section "COPY DATA via rsync"

    local mnt="$(call_hook hook_get_mountpoint "$lv_name")"

    remote "$hyper" "for i in {1..$repeat_count}; do echo round=\$i; $nice $time_cmd rsync $rsync_opt $add_opt $mnt/ $mnt$suffix/; rc=\$?; echo rc=\$rc; if (( !rc || rc == 24 )); then exit 0; fi; echo RESTARTING \$(date); done; echo FAIL; exit -1"
    transfer_quota "$hyper" "$lv_name" "$mnt" "$mnt$suffix"
    remote "$hyper" "sync"
}

function hot_phase
{
    local hyper="$1"
    local primary="$2"
    local secondary_list="$3"
    local lv_name="$4"
    local suffix="${5:-$tmp_suffix}"

    local mnt="$(call_hook hook_get_mountpoint "$lv_name")"
    local vg_name="$(get_vg "$primary")" || fail "cannot determine VG for host '$host'"
    local dev="/dev/$vg_name/$lv_name"
    local dev_tmp="$dev$suffix"
    local mars_dev="/dev/mars/$lv_name"

    # some checks
    section "Checking some preconditions"

    remote "$primary" "if ! [[ -e $dev_tmp ]]; then echo \"Cannot start hot phase: $dev_tmp is missing. Run 'prepare' first!\"; exit -1; fi"
    local host
    for host in $primary $secondary_list; do
	vg_name="$(get_vg "$host")" || fail "cannot determine VG for host '$host'"
	remote "$host" "blkid /dev/$vg_name/$lv_name || true"
	remote "$host" "blkid /dev/$vg_name/$lv_name$suffix || true"
    done

    # additional temporary mount
    make_tmp_mount "$hyper" "$primary" "$lv_name" "$suffix"

    section "Last online incremental rsync"

    copy_data "$hyper" "$lv_name" "$suffix" "time" "$rsync_opt_prepare" "$rsync_repeat_prepare"
    # repeat for better dentry caching
    copy_data "$hyper" "$lv_name" "$suffix" "time" "$rsync_opt_prepare" "$rsync_repeat_prepare"

    call_hook hook_save_local_quota "$hyper" "$lv_name"

    # go offline
    section "Go offline"
    if (( optimize_dentry_cache )) && exists_hook hook_resource_stop_vm ; then
	# retain mountpoints
	call_hook hook_resource_stop_vm "$hyper" "$lv_name"
    else
	optimize_dentry_cache=0
	# stop completely
	call_hook hook_resource_stop "$primary" "$lv_name"

	remote "$primary" "marsadm primary $lv_name"
	if [[ "$primary" != "$hyper" ]]; then
	# create remote devices instead
	    mars_dev="$(call_hook hook_connect "$primary" "$hyper" "$lv_name" 2>&1 | tee /dev/stderr | grep "^NEW_DEV" | cut -d: -f2)"
	    echo "using tmp mars dev '$mars_dev'"
	    [[ "$mars_dev" = "" ]] && fail "cannot setup remote mars device between hosts '$primary' => '$hyper'"
	fi
	remote "$hyper" "mount $mount_opts $mars_dev $mnt/"
    fi

    section "Final rsync"

    copy_data "$hyper" "$lv_name" "$suffix" "time" "$rsync_opt_hot" "$rsync_repeat_hot"

    make_tmp_umount "$hyper" "$primary" "$lv_name" "$suffix"
    remote "$hyper" "rmdir $mnt$suffix || true"
    if (( optimize_dentry_cache )); then
	call_hook hook_resource_stop_rest "$hyper" "$primary" "$lv_name"
    else
	remote "$hyper" "sync; umount $mnt/"
	if [[ "$primary" != "$hyper" ]]; then
	    # remove intermediate remote device
	    sleep 1
	    call_hook hook_disconnect "$primary" "$lv_name"
	fi
    fi

    remote "$primary" "marsadm wait-umount $lv_name"
    remote "$primary" "marsadm secondary $lv_name"

    section "IMPORTANT: destroying the MARS resource"
    echo "In case of failure, you can re-establish MARS resources by hand."
    echo ""

    for host in $secondary_list $primary; do
	remote "$host" "marsadm wait-cluster || echo IGNORE"
	remote "$host" "marsadm down $lv_name"
	remote "$host" "marsadm leave-resource $lv_name || marsadm leave-resource --force $lv_name"
	sleep 3
    done
    remote "$primary" "marsadm delete-resource $lv_name"

    section "CRITICAL: Renaming LVs and re-creating the MARS resource"
    echo "In case of failure, you need to CHECK the correct version by hand."
    echo ""

    for host in $primary $secondary_list; do
	vg_name="$(get_vg "$host")" || fail "cannot determine VG for host '$host'"
	remote "$host" "lvrename $vg_name $lv_name ${lv_name}$shrink_suffix_old"
	remote "$host" "lvrename $vg_name $lv_name$suffix $lv_name"
    done
    remote "$primary" "marsadm create-resource --force $lv_name $dev"
    remote "$primary" "marsadm primary $lv_name"

    section "IMPORTANT: go online again"
    echo "In case of failure, you can re-establish cm3 and MARS resources by hand."
    echo ""

    call_hook hook_resource_start "$primary" "$lv_name"

    section "Re-create the MARS replicas"

    for host in $secondary_list; do
	vg_name="$(get_vg "$host")" || fail "cannot determine VG for host '$host'"
	dev="/dev/$vg_name/${lv_name}"
	if exists_hook hook_join_resource; then
	    call_hook hook_join_resource "$primary" "$host" "$lv_name" "$dev"
	else
	    remote "$host" "marsadm join-resource $lv_name $dev"
	fi
    done

    call_hook hook_restore_local_quota "$hyper" "$lv_name"

    section "Checking new container"

    call_hook hook_resource_check "$lv_name"
}

function cleanup_old_remains
{
    local host_list="$1"
    local lv_name="$2"

    section "Cleanup any old LVs"

    local host
    for host in $host_list; do
	local vg_name="$(get_vg "$host")"
	if [[ "$vg_name" != "" ]]; then
	    make_tmp_umount "$host" "$host" "$lv_name" "$tmp_suffix"
	    section "Removing LVs from $host"
	    remote "$host" "lvremove $lvremove_opt /dev/$vg_name/${lv_name}$tmp_suffix || echo IGNORE LV removal"
	    remote "$host" "lvremove $lvremove_opt /dev/$vg_name/${lv_name}$shrink_suffix_old || echo IGNORE LV removal"
	else
	    echo "ERROR: cannot determine VG for host $host" >> /dev/stderr
	fi
    done
}

######################################################################

# actions for _online_ FS extension / resizing

fs_resize_cmd="${fs_resize_cmd:-xfs_growfs -d}"

function extend_fs
{
    local hyper="$1"
    local primary="$2"
    local secondary_list="$3"
    local lv_name="$4"
    local size="$5"

    local mnt="$(call_hook hook_get_mountpoint "$res")"

    # extend the LV first
    section "Extend the LV"

    local host
    for host in $primary $secondary_list; do
	local vg_name="$(get_vg "$host")" || fail "cannot determine VG for host '$host'"
	local dev="/dev/$vg_name/$lv_name"
	remote "$host" "lvresize -L ${size}k $dev"
    done

    section "Extend the MARS resource"

    remote "$primary" "marsadm resize $lv_name"
    sleep 1

    # propagate new size over intermediate iSCSI
    if [[ "$hyper" != "$primary" ]]; then
	section "propagate new size over iSCSI"
	call_hook hook_extend_iscsi "$hyper"
	sleep 3
    fi

    section "Resize the filesystem"

    remote "$hyper" "$fs_resize_cmd $mnt"
}

######################################################################

# internal actions (using global parameters)

### for migration

function migrate_prepare
{
    call_hook hook_prepare_hosts "$primary $secondary_list $target_primary $target_secondary"

    migration_prepare "$primary" "$res" "$target_primary" "$target_secondary"

    call_hook hook_finish_hosts "$primary $secondary_list $target_primary $target_secondary"
}

function migrate_wait
{
    wait_resource_uptodate "$target_primary $target_secondary" "$res"
}

function migrate_check
{
    call_hook hook_check_migrate "$primary" "$target_primary" "$res"
}

function migrate_finish
{
    migrate_resource "$primary" "$target_primary" "$target_secondary" "$res"
}

function manual_migrate_config
{
    call_hook hook_migrate_cm3_config "$primary" "$target_primary" "$res"
}

function migrate_clean
{
    migrate_cleanup "$to_clean_old" "$to_clean_new" "$res"
    cleanup_old_remains "$to_clean_new" "$res"
}

### for shrinking

function shrink_prepare
{
    create_shrink_space_all "$primary $secondary_list" "$res" "$target_space"
    make_tmp_mount "$hyper" "$primary" "$res"
    copy_data "$hyper" "$res" "$tmp_suffix" "$rsync_nice" "$rsync_opt_prepare" "$rsync_repeat_prepare"
    call_hook hook_save_local_quota "$hyper" "$res"
    if (( !reuse_mount )); then
	make_tmp_umount "$hyper" "$primary" "$res"
    fi
}

function shrink_finish
{
    hot_phase "$hyper" "$primary" "$secondary_list" "$res"
}

function shrink_cleanup
{
    cleanup_old_remains "$primary $secondary_list" "$res"
}

### for extending

function extend_stack
{
    extend_fs "$hyper" "$primary" "$secondary_list" "$res" "$target_space"
}

### global actions

function lv_clean
{
    LV_cleanup "$primary" "$res" 1
}

######################################################################

# MAIN: get and check parameters, determine hosts and resources, run actions

commands_installed "$commands_needed"

ssh-add -l || fail "You must use ssh-agent and ssh-add with the proper SSH identities"

scan_args "$@"

{
echo "$0 $@"

git describe --tags

source_hooks

# special (manual) operations
case "${operation//-/_}" in
manual_config_update)
  call_hook hook_update_cm3_config "$host"
  exit $?
  ;;
esac

# optional: allow syntax "resource:hypervisor:storage"
if [[ "$res" =~ : ]]; then
    rest="${res#*:}"
    res="${res%%:*}"
    if [[ "$rest" =~ : ]]; then
	storage_host[$res]="${rest#*:}"
	rest="${rest%:*}"
    fi
    hypervisor_host[$res]="${rest%:*}"
fi

if [[ "$res" = "" ]]; then
    helpme
    fail "No resource name parameter given"
fi

hyper="$(get_hyper "$res")" || fail "No current hypervisor hostname can be determined"

echo "Determined the following CURRENT hypervisor: \"$hyper\""

if exists_hook hook_get_flavour; then
    flavour="$(hook_get_flavour "$hyper" 2>/dev/null)"
    echo "Determined the following hypervisor FLAVOUR: \"$flavour\""
fi

primary="$(get_store "$res")" || fail "No current primary hostname can be determined"

echo "Determined the following CURRENT primary: \"$primary\""

for host in $hyper $primary; do
    ping -c 1 "$host" > /dev/null || fail "Host '$host' is not pingable"
done

remote "$primary" "mountpoint /mars"
remote "$primary" "[[ -d /mars/ips/ ]]"
remote "$primary" "marsadm view $res"

if (( $(remote "$primary" "marsadm view-is-primary $res") <= 0 )); then
    fail "Resource '$res' on host '$primary' is not in PRIMARY role"
fi

mnt="$(call_hook hook_get_mountpoint "$res")"
if [[ "$mnt" != "" ]]; then
    remote "$hyper" "mountpoint $mnt"
fi

secondary_list="$(remote "$primary" "marsadm view-resource-members $res" | { grep -v "^$primary$" || true; })" || fail "cannot determine secondary_list"

echo "Determined the following secondaries: '$secondary_list'"

for host in $secondary_list; do
    ping -c 1 "$host" || fail "Host '$host' is not pingable"
    remote "$host" "mountpoint /mars > /dev/null"
    remote "$host" "[[ -d /mars/ips/ ]]"
#    if [[ "$operation" =~ migrate ]] && ! [[ "$operation" =~ finish ]]; then
#	local check
#	for check in $target_primary $target_secondary; do
#	    if [[ "$check" = "$host" ]]; then
#		fail "target '$check' is also a secondary - this cannot work"
#	    fi
#	done
#    fi
done

# check connections (only for migration)
if [[ "$operation" =~ migrate ]] && ! [[ "$operation" =~ cleanup|wait ]]; then
    check_migration
fi

if [[ "$operation" = migrate_cleanup ]]; then
    to_clean_old="$(hook_determine_old_replicas "$primary" "$res" 2>&1 | tee /dev/stderr | grep "^FOREIGN" | cut -d: -f2)"
    to_clean_new="$(hook_determine_new_replicas "$primary" "$res" 2>&1 | tee /dev/stderr | grep "^FOREIGN" | cut -d: -f2)"
    if [[ "$to_clean_old$to_clean_new" = "" ]]; then
	echo "NOTHING TO DO"
	exit 0
    fi
    echo "-------------"
    echo "Temporary ${res}${tmp_suffix} partitions + LVs will be removed from:"
    echo "$to_clean_new"
    echo "Stray ${res}${shrink_suffix_old} backup partitions + LVs (old versions before shrinking) will be removed from:"
    echo "$to_clean_old"
elif [[ "$operation" = lv_cleanup ]]; then
    LV_cleanup "$primary" "$res" 0
fi

# determine sizes and available space (only for extending / shrinking)
if [[ "$operation" =~ shrink ]] && ! [[ "$operation" =~ cleanup ]]; then
    determine_space
    check_shrinking
elif [[ "$operation" =~ extend ]]; then
    determine_space
    check_extending
fi

# confirmation

if [[ "$target_primary" != "" ]]; then
    echo "Using the following TARGET primary:   \"$target_primary\""
    echo "Using the following TARGET secondary: \"$target_secondary\""
fi

do_confirm

(( verbose < 1 )) && verbose=1

# main: start the internal actions
echo "START $(date)"

case "${operation//-/_}" in
migrate_prepare)
  migrate_prepare
  ;;
migrate_wait)
  migrate_wait
  ;;
migrate_finish)
  migrate_check
  migrate_finish
  ;;
migrate)
  migrate_check
  migrate_prepare
  migrate_wait
  migrate_finish
  ;;
migrate_cleanup)
  migrate_clean
  ;;

manual_migrate_config)
  migrate_check
  manual_migrate_config
  ;;


shrink_prepare)
  shrink_prepare
  ;;
shrink_finish)
  shrink_finish
  ;;
shrink_cleanup)
  shrink_cleanup
  ;;
shrink)
  shrink_prepare
  shrink_finish
  shrink_cleanup
  ;;

extend)
  extend_stack
  ;;

lv_cleanup)
  lv_clean
  ;;

*)
  helpme
  echo "Unknown operation '$operation'"
  exit -1
  ;;
esac

echo "DONE $(date)"
} 2>&1 | log "$logdir" "logs$args_info.$start_stamp.$LOGNAME.log"
