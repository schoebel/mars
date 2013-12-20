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

#####################################################################

# New modularized version May 2012

shopt -s extdebug

# Make many measurements in subtrees of current working directory.
# Use directory names as basis for configuration variants

script_dir="$(cd "$(dirname "$(which "$0")")"; pwd)"
for lib in $script_dir/modules/lib*.sh; do
    source "$lib" || exit $?
done

to_produce="${to_produce:-replay.gz}"
to_check="${to_check:-}"
to_start="${to_start:-main}"

dry_run_script=0
start_dir=$(pwd)
# all directories between config_root_dir and the actual test directory will be
# considered as "configuration options". That means that a <dirname>.conf file must
# be provided for all these directories
config_root_dir=$start_dir
verbose_script=0

# check some preconditions

check_list="grep sed gawk head tail cut nice date gzip gunzip zcat buffer"
check_installed "$check_list"

# include modules
prepare_list=""
setup_list=""
run_list=""
cleanup_list=""
finish_list=""

function set_host_locks
{
    local host
    if [ ${#main_host_list[*]} -eq 0 ]; then
        lib_vmsg "  warning: main_host_list empty"
        return
    fi
    for host in "${main_host_list[@]}"; do
        local lock_file=${main_lock_file_list[$host]}
        if [ -z "$lock_file" ]; then
            lib_exit 1 "no entry in main_lock_file_list for host $host"
        fi
        if [ -f $lock_file ]; then
            echo "Failure lockfile $lock_file for host $host exists!" >&2
            lib_exit $main_prevent_remove_lock_files_code
        fi
        date > $lock_file || lib_exit 1
        lib_vmsg "  created lockfile $lock_file on $host"
    done
}

function release_host_locks
{
    for host in "${main_host_list[@]}"; do
        local lock_file=${main_lock_file_list[$host]}
        rm -f $lock_file || lib_exit 1
        lib_vmsg "  deleted lockfile $lock_file on $host"
    done
}

function source_module
{
    module="$1"
    modname="$(basename $module | sed 's/^[0-9]*_\([^.]*\)\..*/\1/')"
    if source_config default-$modname; then
        echo "Sourcing module $modname"
        source $module || exit $?
    elif [ "$modname" = "main" ]; then
        echo "Cannot use main module. Please provide some config file 'default-$modname.conf' in $(pwd) or in some parent directory."
        exit -1
    fi
}

shopt -s nullglob
for module in $module_dir/[0-9]*.sh; do
    source_module "$module"
done

# parse options.
while [ $# -ge 1 ]; do
    key="$(echo "$1" | cut -d= -f1)"
    val="$(echo "$1" | cut -d= -f2-)"
    case "$key" in
        --test | --dry-run)
        dry_run_script="$val"
        shift
        ;;
        --override)
        shift
        echo "=> Overriding $1"
        eval $1
        shift
        ;;
        --config_root_dir)
        config_root_dir="$val"
        shift
        ;;
        *)
        break
        ;;
    esac
done

if ! cd $config_root_dir ; then
    echo "cannot cd $config_root_dir" >&2
    exit 1
else
    config_root_dir=$(pwd) # we need the absolute path
    cd $start_dir
fi
ignore_cmd="grep -v '[/.]old' | grep -v 'ignore'"
sort_cmd="while read i; do if [ -e \"\$i\"/prio-[0-9]* ]; then echo \"\$(cd \$i; ls prio-[0-9]*):\$i\"; else echo \"z:\$i\"; fi; done | sort | sed 's/^[^:]*://'"

# find directories
echo "Scanning directory structure starting from $(pwd)"
for test_dir in $(find . -type d | eval "$ignore_cmd" | eval "$sort_cmd"); do
    (( dry_run_script )) || rm -f $test_dir/dry-run.$to_produce
    if [ -e "$test_dir/skip" ]; then
        echo "Skipping directory $test_dir"
        continue
    fi
    if [ $(find $test_dir -type d | eval "$ignore_cmd" | wc -l) -gt 1 ]; then
        echo "Ignoring inner directory $test_dir"
        continue
    fi
    shopt -u nullglob
    if ls $test_dir/*.$to_produce > /dev/null 2>&1; then
        echo "Already finished $test_dir"
        continue
    fi
    if [ -n "$to_check" ] && ! ls $test_dir/*.$to_check > /dev/null 2>&1; then
        echo "No *.$to_check files exist in $test_dir"
        continue
    fi
    echo ""
    echo "==============================================================="
    echo "======== $test_dir"
    if [ -e "$test_dir/stop" ] || [ -e "./stop" ]; then
        echo "would start $test_dir"
        echo "echo stopping due to stop file."
        break
    fi
    (
        cd $test_dir
        
        # to be able to call error recovery functions in case of signals
        trap 'lib_exit 1 "caught signal"' SIGHUP SIGINT

        # source additional user modules (if available)
        source_config "user_modules" || echo "(ignored)"
        shopt -s nullglob
        for module in $user_module_dir/[0-9]*.sh; do
            source_module "$module"
        done

        # source all individual config files (for overrides)
        # between $config_root_dir (exclusive) and $(pwd) (inclusive)
        shopt -s nullglob
        if [ "$test_dir" = "." ]; then
            components=$(basename $(pwd))
        else
            t=$(pwd) # absolute path
            components=$(echo ${t#$config_root_dir/} | sed 's/\// /g')
        fi
        for i in $components; do
            [ "$i" = "." ] && continue
            if ! source_config "$i"; then
                echo "Cannot source config file '$i.conf' -- please provide one."
                exit -1
            fi
        done
        shopt -u nullglob

        export sub_prefix=$(echo $test_dir | sed 's/\//./g' | sed 's/\.\././g')
        if (( dry_run_script )); then
            echo "==> Dry Run ..."
            touch dry-run.$to_produce
        else
            set_host_locks
            echo "==> $(date) Starting $sub_prefix"
            eval "$to_start" # must call exit in case of failure
            release_host_locks
        fi
    )
    rc=$?
    if [ $rc -ne 0 ]; then
        echo "Failure $rc $(date)."
    else
        echo "Finished $(date)."
    fi
    echo "==============================================================="
    [ $rc -ne 0 ] && exit $rc
done

if (( dry_run_script )); then
    echo "removing dry-run.$to_produce everywhere..."
    rm -f $(find . -name "dry-run.$to_produce")
fi

echo "======== Finished pwd=$(pwd)"
exit 0
