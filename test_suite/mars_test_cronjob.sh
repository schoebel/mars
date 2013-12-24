#!/bin/bash
# Copyright 2010-2013 Frank Liepold /  1&1 Internet AG
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

## The scripts starts all tests included in the variable tests_to_execute.
## If you want to see all existing tests, you have to find the leaf directories
## below the directories build_test_environment and test_cases.

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
    local perf_grep_cmd='grep PERFORMANCE-FAILURE '$tmp_file
    local errorfile_grep_cmd='grep ERROR-FILE '$tmp_file
    local kernel_stack_grep_cmd='grep KERNEL-STACK '$tmp_file

    for t in "${!tests_to_execute[@]}"; do
        local config_root_dir=${tests_to_execute[$t]}
        local config_root_dir_opt=${config_root_dir:+"--config_root_dir=$test_suite_dir/$config_root_dir"}
        echo executing test $t
        cd $test_suite_dir/$t || myexit 1
        $start_script $config_root_dir_opt 2>&1 |  tee $tmp_file
        rc=${PIPESTATUS[0]}
        if [ $rc -ne 0 ];then
            fail_msg+="$t"$'\n'
            send_msg=1
        fi
        if $perf_grep_cmd >/dev/null; then
            perf_msg+="$t: $($perf_grep_cmd)"$'\n'
            send_msg=1
        fi
        if $errorfile_grep_cmd >/dev/null; then
            errorfile_msg+="$t: $($errorfile_grep_cmd)"$'\n'
            send_msg=1
        fi
        if $kernel_stack_grep_cmd >/dev/null; then
            kernel_stack_msg+="$t: $($kernel_stack_grep_cmd)"$'\n'
            send_msg=1
        fi
        if [ $rc -ne 0 -a $continue_after_failed_test -eq 0 ];then
            break
        fi
    done
    rm $tmp_file
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
    echo "usage: $my_name [-e] test_suite_dir" >&2
    echo "          -e: dont't continue if a test fails" >&2
    exit 1
}

# main
my_name=$(basename $0)

OPTSTR="e"

continue_after_failed_test=1

while getopts "$OPTSTR" opt; do
    case $opt in # (
        e) continue_after_failed_test=0;;
        *) usage;;
    esac
done

[ $# -ne 1 ] && usage

test_suite_dir=$1

# main

echo Start $(basename $0) at $(date)

eval $(ssh-agent)
~/tools/sx

mail_server=mxintern.schlund.de:587

mail_from="$0@$(hostname)"
mail_to=("frank.liepold@1und1.de")


start_script=$test_suite_dir/scripts/start_test.sh

# key = test directory, value = directory serving as parameter for option
# --config_root_dir of start_test.sh
# all directory paths are given relative to test_suite_dir

declare -A tests_to_execute
tests_to_execute=(\
["build_test_environment/checkout"]="build_test_environment" \
["build_test_environment/make/make_mars/grub"]="build_test_environment" \
["build_test_environment/install_mars"]="build_test_environment" \
["build_test_environment/lv_config"]="build_test_environment" \
["build_test_environment/cluster"]="build_test_environment" \
["build_test_environment/resource/create_resource"]="build_test_environment" \
["test_cases/admin/apply_fetch/apply"]="test_cases/admin" \
["test_cases/admin/apply_fetch/fetch"]="test_cases/admin" \
["test_cases/hardcore/destroy_secondary_logfile"]="test_cases/hardcore" \
["test_cases/admin/resizing"]="test_cases/admin" \
["test_cases/admin/logrotate"]="test_cases/admin" \
["test_cases/admin/logdelete"]="test_cases/admin" \
["test_cases/bugs/memleak"]="test_cases/bugs" \
["test_cases/admin/switch2primary"]="test_cases/admin" \
["test_cases/admin/switch2primary_force"]="test_cases/admin" \
["test_cases/admin/datadev_full"]="test_cases/admin" \
["test_cases/hardcore/mars_dir_full/write_other_file"]="test_cases/hardcore" \
["test_cases/hardcore/mars_dir_full/write_data_dev"]="test_cases/hardcore" \
["test_cases/stabil/net_failure/connection_cut"]="test_cases/stabil" \
["test_cases/admin/three_nodes"]="test_cases/admin" \
["test_cases/admin/switch2primary_force"]="test_cases/admin" \
["test_cases/stabil/crash/crash_primary"]="test_cases/stabil" \
["test_cases/stabil/crash/crash_primary_logger_comletion_semantics__aio_sync_mode"]="test_cases/stabil" \
["test_cases/stabil/crash/crash_primary_logger_completion_semantics"]="test_cases/stabil" \
["test_cases/stabil/crash/crash_primary_aio_sync_mode"]="test_cases/stabil" \
["test_cases/bugs/aio_filehandle"]="test_cases/bugs" \
["build_test_environment/resource/leave_resource"]="test_cases/admin" \
["test_cases/perf"]="" \
)

tests_to_execute=(\
["build_test_environment/resource/create_resource"]="build_test_environment" \
)
set_env

execute_tests

rc=$?

echo End $(basename $0) at $(date)
