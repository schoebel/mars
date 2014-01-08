#!/usr/bin/env bash
# Copyright 2010-2012 Thomas Schoebel-Theuer /  1&1 Internet AG
#
# Email: tst@1und1.de 
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

# this may be later overridden by distros / install scripts / etc

# $sript_dir is assumed to be already set by the caller
base_dir="$(cd "$script_dir/.."; pwd)"
bin_dir="$base_dir/src"
module_dir="$script_dir/modules"
download_dir="$base_dir/downloads"
mkdir -p "$download_dir" || exit -1

[ -x $bin_dir/bins.exe ] || \
    (cd $base_dir && ./configure && make) ||\
    { echo "Could not make binaries. Sorry." ; exit -1; }

#####################################################################

# general error exit function
function lib_callstack
{
    echo "========================== Callstack ==========================================="
    local argv_index=0 i
    for i in ${!FUNCNAME[*]}; do
        local j args=
        argc=${BASH_ARGC[$i]}
        if [ ${argc:-0} -gt 0 ]; then
            for j in $(seq 1 1 $argc); do
                args='"'"${BASH_ARGV[$argv_index]}"'" '"$args"
                let argv_index+=1
            done
        fi
        echo ${BASH_SOURCE[(($i + 1))]:-"stdin"}:${BASH_LINENO[$i]} ${FUNCNAME[$i]} $args
    done
    echo "========================== End callstack ======================================="
}

function lib_exit
{
    local rc=$1 msg="$2"
    if [ -n "$msg" ];then
        echo "  $msg" >&2
    fi
    if [ $rc -ne 0 ]; then
        lib_callstack >&2
    fi
    if [ $rc -ne $main_prevent_remove_lock_files_code ]; then
        release_host_locks
    fi
    # to avoid recursion
    if [ -n "$lib_exit_recursion" ];then
        echo "lib_exit:recursion!!!" >&2
        printf "\nstack:\n" >&2
        lib_callstack >&2
        exit $rc
    fi
    export lib_exit_recursion=1
    lib_general_checks_after_every_test
    if [ ${#main_error_recovery_functions[*]} -ge 0 ]; then
        local func args
        for func in "${!main_error_recovery_functions[@]}"; do
            args="${main_error_recovery_functions[$func]}"
            if [ -n "$args" ];then
                echo "  calling error recovery $func" >&2
                $func $args || exit 1
            fi
        done
    fi
    exit $rc
}

#####################################################################


# helper to generate verbose messages

function lib_vmsg
{
    if (( verbose_script )); then
        echo "$(date +'%Y-%m-%d %H:%M:%S') ${BASH_SOURCE[1]}:${BASH_LINENO[0]}: $* [[$(
        for i in $(seq $((${#BASH_SOURCE[@]} - $main_min_stack_level)) -1 1); do
            printf '%s' $prefix$(basename ${BASH_SOURCE[$i]}):${BASH_LINENO[$(($i - 1))]}
            prefix='->'
        done
      )]]"
    fi
}



#####################################################################

# helper for prevention of script failures due to missing tools

function check_installed
{
    local check_list="$1" i
    for i in $check_list; do
	if ! which $i >/dev/null 2>&1; then
	    echo "Sorry, program '$i' is not installed."
	    exit -1
	fi
    done
}

check_always_list="basename dirname which pwd mkdir rmdir rm cat ls sort ssh scp nice sed awk"
check_installed "$check_always_list"

#####################################################################

# helper for sourcing other config files (may reside in parents of cwd)

function source_config
{
    local name="$1"
    local setup_dir=$(pwd)
    local limit=0
    until [ -r $setup_dir/$name.conf ]; do
	setup_dir="$(cd $setup_dir/..; pwd)"
	(( limit++ > 20 )) && { echo "No parent dir found for (potential) config file $name.conf."; return 1; }
    done
    local setup=$setup_dir/$name.conf
    echo "Sourcing config file $setup"
    shopt -u nullglob
    source $setup || exit $?
    return 0
}

#####################################################################

# abstracting access to remote hosts

function lib_remote_opt
{
    local ssh_opt="$1"
    shift
    local host="$1"
    shift
    ssh $ssh_opt -n root@"$host" "$@"
}

function remote
{
    lib_remote_opt "" "$@"
}


function lib_remote_all_idfile
{
    lib_remote_all_opt "$main_ssh_idfile_opt" "$@"
}

function lib_remote_all_opt
{
    local ssh_opt="$1"
    shift
    local host_all="$1" host
    shift
    local cmd="$@"
    for host in $host_all; do
	    lib_remote_opt "$ssh_opt" "$host" "$cmd" \
                || { rc=$?; echo "  $cmd cmd failed on host $host" >&2; return $rc; }
    done
}

function remote_all
{
    lib_remote_all_opt "" "$@"
}

function lib_remote_idfile
{
    lib_remote_opt "$main_ssh_idfile_opt" "$@"
}

function remote_all_noreturn
{
    local host_all="$1" host
    shift
    for host in $host_all; do
	remote "$host" "$@"
    done
}

function lib_check_access_to_remote_hosts 
{
    local ssh_opt="$1"
    shift
    local hostlist="$@"
    if (( verbose_script )); then
        echo "  testing access as root to hosts $hostlist"
    fi
    lib_remote_all_opt "$ssh_opt" "$hostlist" hostname || lib_exit 1
}

# The pid of the started program will be returned in the variable named by
# $3.
# The names of the script which is executed on the remote host will be returned
# in the variable namend by $4
# The name of the (remote) outputfile of the script is the script name
# extended with .out
# stdout resp. stderr are kept in files named <script>.out resp. <script>.err on the remote host.
function lib_start_script_remote_bg
{
    [ $# -eq 5 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local host=$1 script=$2 varname_pid=$3 varname_script=$4 rm_opt=$5
    local ssh_opt="$main_ssh_idfile_opt"
    if [ ! -f $script ]; then
        lib_exit 1 "script file $script not found"
    fi
    chmod ugo+x $script || lib_exit 1 "cannot chmod $script"

    local remote_filename=/tmp/$(basename $script)
    lib_vmsg "  copying script $script to $host:$remote_filename"
    scp $ssh_opt $script root@$host:$remote_filename || lib_exit 1

    if [ $rm_opt = "rm" ]; then
        rm -f $script || lib_exit 1
    fi

    local remote_pid
    local cmd="/bin/bash $remote_filename >$remote_filename.out 2>$remote_filename.err"
    local error_hint="see also $remote_filename.out resp. $remote_filename.err"
    lib_vmsg "  executing $cmd on $host"
    remote_pid=$(ssh -n $ssh_opt root@$host ''"$cmd"' & echo $!') || lib_exit 1 "$error_hint"

    lib_vmsg "  checking whether process $remote_pid is running on $host"
    ssh -n $ssh_opt root@$host ps -fp $remote_pid || lib_exit 1 "$error_hint"

    lib_vmsg "  checking whether process $remote_pid has errors in $remote_filename.err"
    ssh -n $ssh_opt root@$host "if [ -s $remote_filename.err ]; then cmd='kill -1 $remote_pid'; echo \$cmd; \$cmd; cat $remote_filename.err; exit 1; fi"  || lib_exit 1

    eval $varname_pid=$remote_pid
    eval $varname_script=$remote_filename
}

## copy a file from a remote host to a local target
function lib_cp_remote_file
{
    local host=$1 remote_filename=$2 local_filename=$3
    local ssh_opt="$main_ssh_idfile_opt"
    lib_vmsg "  cp $host:$remote_filename -> $local_filename"
    scp $ssh_opt root@$host:$remote_filename $local_filename || lib_exit 1
}



#####################################################################

# generate copyright header on stdout

function echo_copyright
{
    local name="$1"
    local copyright="${2:-Thomas Schoebel-Theuer /  1&1 Internet AG}"

    # Notice: the following GNU all-permissive license applies to the
    # generated DATA file only, and does not change the GPL of this script.
    #
    echo "Copyright $copyright"
    echo ""
    if [ -n "$name" ]; then
	echo "This file was automatically generated from '$name'"
	echo "converted by $(whoami)@$(hostname) $(date)"
	echo ""
    fi
    echo "PLEASE DO NOT EDIT this file without renaming, even if legally"
    echo "allowed by the following GNU all-permissive license:"
    echo ""
    echo "Copying and distribution of this file, with or without modification,"
    echo "are permitted in any medium without royalty provided the copyright"
    echo "notice and this notice are preserved.  This file is offered as-is,"
    echo "without any warranty."
    echo ""
    echo "PLEASE name any derivatives of this file DIFFERENTLY, in order to"
    echo "avoid confusion. Additionally, PLEASE add a pointer to the original."
    echo ""
    echo "PLEASE means: failing to do so may damage your reputation."
    echo ""
    echo "Why? Because people EXPECT that 'things' remain the same, otherwise"
    echo "they may accuse you of winding them up."
    echo ""
    echo "Notice: damaged reputation can be harder than prison. I have warned you."
    echo ""
    echo "In practice: although I don't put a 'hard' requirement on you,"
    echo "PLEASE just copy/rename this file before doing"
    echo "any modifications, and include a pointer to the original."
    echo ""
    echo "Additionally, it is best practice to name your data files such that"
    echo "other people can easily grasp what is inside."
    echo ""
    echo "#################################################################"
}
