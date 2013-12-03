#!/bin/bash


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

    for t in "${tests_to_execute[@]}"; do
        echo executing test $t
        cd $test_suite_dir/$t || myexit 1
        $start_script 2>&1 |  tee $tmp_file
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
    done
    rm $tmp_file
    if [ $send_msg -eq 1 ]; then
        local to
        local msg="$fail_msg$perf_msg$errorfile_msg$kernel_stack_msg"$'\n'
        msg+="for details see logfile on $(hostname)"
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
    echo "usage: $my_name [-c] test_suite_dir" >&2
    echo "          -c: without cleanup after all tests have passed" >&2
    echo "          -b: checkout, install, build resource" >&2
    exit 1
}

# main
my_name=$(basename $0)

OPTSTR="bc"

with_cleanup=0
only_checkout_install_build_resource=0

while getopts "$OPTSTR" opt; do
    case $opt in # (
        c) with_cleanup=0;;
        b) only_checkout_install_build_resource=1;;
        *) usage;;
    esac
done

[ $# -ne 1 ] && usage

test_suite_dir=$1

# main

echo Start $(basename $0) at $(date)
logfile="/home/fl/tmp/cronjob_mars.log"

eval $(ssh-agent)
~/tools/sx

mail_server=mxintern.schlund.de:587

mail_from="$0@$(hostname)"
mail_to=("frank.liepold@1und1.de")


start_script=$test_suite_dir/scripts/start_test.sh

# test entries *must* start at begin of lines

tests_to_execute=(\
build_test_environment/checkout \
build_test_environment/make/make_mars/grub \
build_test_environment/install_mars \
build_test_environment/lv_config \
build_test_environment/cluster \
build_test_environment/resource/create_resource \
test_cases/admin/apply_fetch/apply \
test_cases/admin/apply_fetch/fetch \
test_cases/destroy_secondary_logfile \
test_cases/admin/resizing \
test_cases/admin/logrotate \
test_cases/admin/logdelete \
test_cases/bugs/memleak \
test_cases/admin/switch2primary \
test_cases/admin/datadev_full \
test_cases/hardcore/mars_dir_full/write_other_file \
test_cases/hardcore/mars_dir_full/write_data_dev \
test_cases/stabil/net_failure/connection_cut \
test_cases/admin/three_nodes \
test_cases/stabil/crash/crash_primary \
test_cases/stabil/crash/crash_primary_logger_comletion_semantics__aio_sync_mode \
test_cases/stabil/crash/crash_primary_logger_completion_semantics \
test_cases/stabil/crash/crash_primary_aio_sync_mode \
test_cases/bugs/aio_filehandle \
build_test_environment/resource/leave_resource \
test_cases/perf \
)

if [ $only_checkout_install_build_resource -eq 1 ]; then
    tests_to_execute=(\
        build_test_environment/checkout \
        build_test_environment/make \
        build_test_environment/install_mars \
        build_test_environment/lv_config \
        build_test_environment/cluster \
        build_test_environment/resource/create_resource \
    )
fi

set_env

execute_tests

rc=$?

if [ $rc -eq 0 -a $with_cleanup -eq 1 ];then
    tests_to_execute=(build_test_environment/resource/cleanup_resource)
    execute_tests
fi


echo End $(basename $0) at $(date)
