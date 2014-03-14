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

## The scripts starts all tests included in the array tests_to_execute.
## The values in this array consist of two directories separated by a colon:
##
## directory-1:directory-2
##
## directory-1 is the directory from where start_test.sh is called (the
## "start directory" mentioned in README).
## You can use a * at the end of the name of directory-1 which causes that
## all subdirectories in the directory tree starting at directory-1 
## which contain a file named i_am_a_testdirectory define a start directory
## from which start_test.sh is called.
## 
## directory-2 serves as parameter for option --config_root_dir of start_test.sh
##
# All directory paths are given relative to use_case_dir

function myexit
{
    local rc=$1 msg="$2"
    if [ -n "$msg" ];then
        echo "  $msg" >&2
    fi
    echo "  exit called from ${BASH_SOURCE[1]}:${BASH_LINENO[0]}" >&2
    exit $rc
}

function execute_tests
{
    local t rc send_msg=0
    local tmp_file=/tmp/$my_name.$$
    local fail_msg="tests failed on $(hostname) (Script $0):"$'\n'
    local perf_msg="Performance-Failures:"$'\n'
    local errorfile_msg="Error-Files:"$'\n'
    local kernel_stack_msg="Kernel-Stacks:"$'\n'
    local perf_grep_cmd="grep '^ *PERFORMANCE-FAILURE' "$tmp_file
    local errorfile_grep_cmd="grep 'ERROR-FILE' "$tmp_file
    local kernel_stack_grep_cmd="grep 'KERNEL-STACK' "$tmp_file

    for t in "${tests_to_execute[@]}"; do
        local test_dir="${t%:*}" start_dirs s
        local config_root_dir=${t#*:}
        local config_root_dir_opt=${config_root_dir:+"--config_root_dir=$use_case_dir/$config_root_dir"}
        case "$test_dir" in # ((
            *\*) test_dir=${test_dir%\*}
                 start_dirs=($(find $use_case_dir/$test_dir -type f \
                                    -name i_am_a_testdirectory -exec \
                                    dirname {} \;)
                            )
                 ;;
               *) start_dirs=($use_case_dir/$test_dir)
                 ;;
        esac
        for s in "${start_dirs[@]}"; do
            echo executing test $s
            if [ $dry_run -eq 1 ]; then
                continue
            fi
            cd $s || myexit 1
            $start_script $config_root_dir_opt 2>&1 |  tee $tmp_file
            rc=${PIPESTATUS[0]}
            if [ $rc -ne 0 ];then
                fail_msg+="$s"$'\n'
                send_msg=1
            fi
            if eval $perf_grep_cmd >/dev/null; then
                perf_msg+="$s: $(eval $perf_grep_cmd)"$'\n'
                send_msg=1
            fi
            if eval $errorfile_grep_cmd >/dev/null; then
                errorfile_msg+="$s: $(eval $errorfile_grep_cmd)"$'\n'
                send_msg=1
            fi
            if eval $kernel_stack_grep_cmd >/dev/null; then
                kernel_stack_msg+="$s: $(eval $kernel_stack_grep_cmd)"$'\n'
                send_msg=1
            fi
            if [ $rc -ne 0 -a $continue_after_failed_test -eq 0 ];then
                break
            fi
        done
    done
    rm -f $tmp_file
    if [ $send_msg -eq 1 ]; then
        local to
        local msg="$fail_msg$perf_msg$errorfile_msg$kernel_stack_msg"$'\n'
        for to in "${mail_to[@]}"; do
                sendEmail -m "$msg" -f $mail_from -t $to -u "failed mars tests" -s $mail_server
        done
        echo "$msg"
        return 1
    else
        echo all tests passed
        return 0
    fi
}

function set_env
{
    export PATH=$PATH:/sbin
}

function usage
{
    echo "usage: $my_name [-e] [-l] test_suite_dir use_case_dir" >&2
    echo "          -e: dont't continue if a test fails" >&2
    echo "          -l: list all tests which will be executed but don't execute them" >&2
    exit 1
}

# main
my_name=$(basename $0)

OPTSTR="el"

continue_after_failed_test=1
dry_run=0

while getopts "$OPTSTR" opt; do
    case $opt in # (
        e) continue_after_failed_test=0;;
        l) dry_run=1;;
        *) usage;;
    esac
done

shift $(($OPTIND - 1))

[ $# -ne 2 ] && usage

test_suite_dir=$1
use_case_dir=$2

for n in test_suite use_case;do
    eval d='$'${n}_dir
    if [ ! -d $d ]; then
        echo "directory ${n}_dir = $d not found" >&2
        exit 1
    fi
done


# main

echo Start $(basename $0) $test_suite_dir $use_case_dir at $(date)

mail_server=mxintern.schlund.de:587

mail_from="$0@$(hostname)"
mail_to=("frank.liepold@1und1.de")


start_script=$test_suite_dir/scripts/start_test.sh

# For documentation see header of this file
tests_to_execute=(
"build_test_environment/lv_config/lv_recreate:build_test_environment"
"build_test_environment/cluster/create_cluster:build_test_environment"
"build_test_environment/resource/create_resource:build_test_environment"
"test_cases/admin/leave_and_recreate_resource:test_cases"
"test_cases/admin/apply_fetch/apply:test_cases"
"test_cases/admin/apply_fetch/fetch:test_cases"
"test_cases/hardcore/destroy_secondary_logfile:test_cases"
"test_cases/admin/multi_res_sync_sequence:test_cases"
"test_cases/admin/resizing:test_cases"
"test_cases/admin/logrotate:test_cases"
"test_cases/admin/logdelete:test_cases"
"test_cases/admin/syslog_messages:test_cases"
"test_cases/bugs/memleak:test_cases"
"test_cases/admin/leave_resource_while_sync*:test_cases"
"test_cases/admin/switch2primary:test_cases"
"test_cases/admin/switch2primary_force*:test_cases"
"test_cases/admin/datadev_full:test_cases"
"test_cases/hardcore/mars_dir_full*:test_cases"
"test_cases/stabil/net_failure/connection_cut:test_cases"
"test_cases/admin/three_nodes:test_cases"
"test_cases/stabil/crash/crash_primary:test_cases"
"test_cases/stabil/crash/crash_primary_logger_comletion_semantics__aio_sync_mode:test_cases"
"test_cases/stabil/crash/crash_primary_logger_completion_semantics:test_cases"
"test_cases/stabil/crash/crash_primary_aio_sync_mode:test_cases"
"test_cases/bugs/aio_filehandle:test_cases"
"test_cases/perf:"
)

set_env

execute_tests

rc=$?

echo End $(basename $0) at $(date)
