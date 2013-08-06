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
    local t rc
    for t in "${tests_to_execute[@]}"; do
        echo executing test $t
        cd $test_base/$t || myexit 1
        $start_script
        rc=$?
        if [ $rc -ne 0 ];then
            failed_tests[${#failed_tests[*]}]="$t"
        fi
    done

    if [ ${#failed_tests[*]} -ne 0 ];then
        local to msg
        msg="tests failed on $(hostname) (Script $0):
    ${failed_tests[@]}
for details see $logfile on $(hostname)"
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
    echo "usage: $(basename $0) [-c]" >&2
    echo "          -c: without cleanup after all tests have passed" >&2
    echo "          -b: checkout, install, build resource" >&2
    exit 1
}

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

# main
echo Start $(basename $0) at $(date)
logfile="/home/fl/tmp/cronjob_mars"

eval $(ssh-agent)
~/tools/sx

mail_server=mxintern.schlund.de:587

mail_from="$0@$(hostname)"
mail_to=("frank.liepold@1und1.de")

test_base=~fl/mars/test_suite

start_script=$test_base/scripts/start_test.sh

tests_to_execute=(\
build_test_environment/checkout \
build_test_environment/make \
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
test_cases/perf \
test_cases/admin/switch2primary \
test_cases/admin/datadev_full \
test_cases/hardcore/mars_dir_full/write_other_file \
test_cases/hardcore/mars_dir_full/write_data_dev \
test_cases/stabil/net_failure/connection_cut \
test_cases/stabil/crash/crash_primary \
test_cases/stabil/crash/crash_primary_logger_comletion_semantics__aio_sync_mode \
test_cases/stabil/crash/crash_primary_logger_completion_semantics \
test_cases/stabil/crash/crash_primary_aio_sync_mode \
test_cases/hardcore/aio_filehandle \
build_test_environment/resource/leave_resource \
)

if [ $only_checkout_install_build_resource -eq 1 ]; then
    tests_to_execute=(
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
