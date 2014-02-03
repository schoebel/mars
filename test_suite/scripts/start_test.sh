#!/bin/bash
# Copyright 2010-2014 Frank Liepold /  1&1 Internet AG
#
# Email: frank.liepold@1und1.de
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

## For a general documentation please refer to README, section "Running a test"

function set_host_locks
{
    local host
    if [ ${#main_host_list[*]} -eq 0 ]; then
        lib_vmsg "  warning: main_host_list empty"
        return
    fi
    echo "================= Creating lock files =========================================="
    for host in "${main_host_list[@]}"; do
        local lock_file=${main_lock_file_list[$host]}
        if [ -z "$lock_file" ]; then
            lib_exit 1 "no entry in main_lock_file_list for host $host"
        fi
        if [ -f $lock_file ]; then
            echo "Failure lockfile $lock_file for host $host exists!" >&2
            lib_exit $main_prevent_remove_lock_files_exit_code
        fi
        date > $lock_file || lib_exit 1
        lib_vmsg "  created lockfile $lock_file on $host"
    done
    echo "================= End creating lock files ======================================"
}

function release_host_locks
{
    echo "================= Deleting lock files =========================================="
    for host in "${main_host_list[@]}"; do
        local lock_file=${main_lock_file_list[$host]}
        rm -f $lock_file || lib_exit 1
        lib_vmsg "  deleted lockfile $lock_file on $host"
    done
    echo "================= End deleting lock files ======================================"
}

function source_module
{
    module="$1"
    modname="$(basename $module | sed 's/^[0-9]*_\([^.]*\)\..*/\1/')"
    if source_config default-$modname; then
        echo "Sourcing module $modname"
        source $module || start_test_exit $?
    elif [ "$modname" = "main" ]; then
        echo "Cannot use main module. Please provide some config file 'default-$modname.conf' in $(pwd) or in some parent directory."
        start_test_exit -1
    fi
}

function save_environment
{
    # we cannot use lib_exit because the libs are not yet sourced in
    environ_save=/tmp/environ.sav.$$
    rm -f $environ_save || lib_exit 1 "cannot remove $environ_save"
    set >$environ_save || lib_exit 1 "cannot create $environ_save"
}

# prints all shell variables which are set via sourcing the *.conf files
function print_config_environment
{
    local f
    local environ_actual=/tmp/environ.act.$$
    [ -n "$environ_save" ] || lib_exit 1 "variable environ_save not set"
    [ -r "$environ_save" ] || lib_exit 1 "file $environ_save not readable"
    rm -f $environ_actual || lib_exit 1 "cannot remove $environ_actual"
    set >$environ_actual || lib_exit 1 "cannot create $environ_actual"
    # delete function definitions and sort
    for f in $environ_save $environ_actual; do
        sed -i -e '/^.* () *$/d;/^{ *$/,/^} *$/d' $f || lib_exit 1
        sort -o $f $f || lib_exit 1
    done

    echo "================= Configuration variables ======================================"
    # print lines uniq to $environ_actual and remove some not interesting
    # variables
    comm -2 -3 $environ_actual $environ_save | \
        egrep -v '^(BASH_LINENO|FUNCNAME|OLDPWD|_)='
    rm -f $environ_actual
    echo "================= End configuration variables =================================="
    
}

function usage
{
    echo "usage: $(basename $0) [--dry-run] [--config_root_dir=<my_dir>]" >&2
    echo "          Option --dry-run:" >&2
    echo "               Print all configuration variables and the name " >&2
    echo "               of the test. Don't execute it." >&2
    echo "          Option --config_root_dir:" >&2
    echo "               Include all *.conf files belonging to subdirectories " >&2
    echo "               between my_dir and test directory." >&2
    echo "               Default: my_dir = working directory" >&2
    exit 1
}

dry_run_script=0
start_dir=$(pwd)
# all directories between config_root_dir and the actual test directory will be
# considered as "configuration options". That means that a <dirname>.conf file
# must be provided for all these directories
config_root_dir=$start_dir
verbose_script=1

# parse options.
while [ $# -ge 1 ]; do
    key="$(echo "$1" | cut -d= -f1)"
    val="$(echo "$1" | cut -d= -f2-)"
    case "$key" in
        --dry-run)
                    dry_run_script="$val"
                    shift
                    ;;
        --config_root_dir)
                    config_root_dir="$val"
                    shift
                    ;;
        *)
                    usage
        ;;
    esac
done

if ! cd $config_root_dir ; then
    echo "cannot cd $config_root_dir" >&2
    start_test_exit 1
else
    config_root_dir=$(pwd) # we need the absolute path
    cd $start_dir
fi

# wrapper for the exit builtin to be able to remove temporary files
function start_test_exit
{
    rm -f $environ_save
    exit $1
}

shopt -s extdebug

# Use directory names as basis for configuration variants

script_dir="$(cd "$(dirname "$(which "$0")")"; pwd)"
lib_dir=$script_dir/modules
echo "================= Sourcing libraries in $lib_dir ==============================="
for lib in $lib_dir/lib*.sh; do
    echo "Sourcing $lib"
    source "$lib" || start_test_exit $?
done
echo "================= End sourcing libraries ======================================="

to_start="${to_start:-main}"
marker_file="i_am_a_testdirectory"

# check some preconditions

check_list="grep sed gawk head tail cut nice date gzip gunzip zcat buffer"
check_installed "$check_list"

# include modules
prepare_list=""
setup_list=""
run_list=""
cleanup_list=""
finish_list=""

save_environment # for later use in print_config_environment

shopt -s nullglob
echo "================= Sourcing modules and default configuration ==================="
for module in $module_dir/[0-9]*.sh; do
    source_module "$module"
done
echo "================= End sourcing modules and default configuration ==============="

# find directories
echo "================= Scanning subdirectories of $start_dir ========================"
for marker in $(find . -type f -name "$marker_file"); do
    test_dir=$(dirname $marker)
    shopt -u nullglob
    (
        cd $test_dir
        echo "================= Test directory $(pwd) $date =================================="
        echo "================= Sourcing config files between $config_root_dir and $(pwd) ===="
        
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
        t=$(pwd) # absolute path
        if [ "$t" = "$config_root_dir" ]; then
            components=$(basename $(pwd))
        else
            components=$(echo ${t#$config_root_dir/} | sed 's/\// /g')
        fi
        for i in $components; do
            [ "$i" = "." ] && continue
            if ! source_config "$i"; then
                echo "Cannot source config file '$i.conf' -- please provide one."
                start_test_exit -1
            fi
        done
        echo "================= End sourcing config files between $config_root_dir and $(pwd) "
        print_config_environment
        shopt -u nullglob

        if (( dry_run_script )); then
            echo "would start $(pwd)"
            exit 0
        else
            set_host_locks
            echo "================= Starting $(pwd) $(date) ======================================"
            eval "$to_start"
            test_rc=$?
            release_host_locks
            exit $test_rc
        fi
    )
    rc=$?
    if [ $rc -ne 0 ]; then
        echo "========================== Failure $rc $(cd $test_dir; pwd) $date ==============" >&2
    else
        echo "========================== Finished $(cd $test_dir; pwd) $(date) ==============="
    fi
    [ $rc -ne 0 ] && start_test_exit $rc
done

echo "========================== Finished start directory $start_dir ================="
start_test_exit 0
