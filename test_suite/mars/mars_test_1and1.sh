#!/bin/bash
# Copyright 2010-2014 Frank Liepold /  1&1 Internet AG
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

#
# - install the build tools from branch MARS_BUILD_TOOLS_BRANCH of repo
#   MARS_BUILD_TOOLS_REPO (function checkout_build_tools)
#
# - build a mars module from a given branch GIT_UPSTREAM_BRANCH of repo
#   GIT_UPSTREAM (function build_module)
#
# - disable sync on the MARS_TEST_HOSTS TODO
#
# - install the mars modules on the MARS_TEST_HOSTS
#   (function install_module_on_hosts)
#
# - run mars test suite from branch GIT_TEST_SUITE_BRANCH of repo GIT_TEST_SUITE
#   on MARS_TEST_HOSTS (function run_tests)
#
# - if all tests passed, then reenable sync on the MARS_TEST_HOSTS TODO
#
# Output and mailing:
# The crontab entry calling this script defines the file to which the output
# is redirected. It should reside in MARS_CRONJOB_DIR.
# The outputs of mars_test_cronjob.sh reside in LOGFILE_DIR
# The repositories are unpacked in temp. directories /tmp/tmp.*
# Mars error and log files are saved in the test case directory, e.g.
# (let the tmp directory be /tmp/tmp.3bs4KX30mH):
# if the test case 
# 
# test_cases/admin/switch2primary_force/logrot_spl_brain_orig_secon/logrot_orig_prim/not_connected/data_dev_not_in_use/secon_becomes_prim/i_am_a_testdirectory
#
# generates an error file or error messages in 5.mars.total.log, the error file
# or 5.mars.total.log is fetched from the test host in the directory
#
# /tmp/tmp.3bs4KX30mH/test_suite/test_suite/mars/test_cases/admin/switch2primary_force/logrot_spl_brain_orig_secon/logrot_orig_prim/not_connected/data_dev_not_in_use/secon_becomes_prim/i_am_a_testdirectory
#
# TODO regular cleanup of the tmp directories

# Mail recipients are given via MARS_MAIL_TO
# 
# Access requirements:
# The test hosts must be accessible via ssh -i MARS_SSH_KEYFILE without
# prompting for a pathword. For further requirements concerning access
# permissions see the test_suite/README file of the mars repository.
#
# Interfaces used in this script:
#
# - build_snapshot.sh and build_snapshot_modules.sh  from
#   ssh://git@git.schlund.de/debian/mars.git
#   see Subsection build mars module variables 
#   ATTENTION: Because we poll for the packages to be built on the build host
#              we assume certain patterns in the package names which may
#              be subject to change ...
#              See the following variables:
#              BUILD_UI, BUILD_SNAPSHOT_PATTERN, BUILD_SNAPSHOT_MODULES_PATTERN,

# Author: Frank Liepold <frank.liepold@1und1.de>

# ---------------- Section: global variables ----------------------------------

WORKING_DIR=/mars

# directory of mars_test_cronjob's outputs
LOGFILE_DIR=$WORKING_DIR/log

# directory of the cronjob's outputs
MARS_CRONJOB_DIR=$WORKING_DIR/cron_log

# file where stdout and stderr are written to. Must be set by caller. If not
# empty it will be attached to the emails sent in case of errors.
MARS_CRON_OUT=${MARS_CRON_OUT:-"no logfile specified by caller"}

# array containing the hosts on which the test suite will be started.
# every two hosts are considered as a mars cluster 
MARS_TEST_HOSTS=(istore-test-bs7 istore-test-bap7 ovzd-test-bs1 ovzd-test-bap1)


# ---------- Subsection mail and access variables -----------------------------

# MARS_SSH_KEYFILE, MARS_MAIL_SERVER_AND_PORT and MARS_MAIL_TO are used in 
# GIT_TEST_SUITE/test_suite/mars/mars_test_cronjob.sh.
# therefore they are exported.
export MARS_SSH_KEYFILE=~/.ssh/marstester
export MARS_MAIL_SERVER_AND_PORT=${MARS_MAIL_SERVER_AND_PORT:-"mintern.schlund.de:25"}
export MARS_MAIL_TO=${MARS_MAIL_TO:-"frank.liepold@1und1.de"}
# string which appears as sender of the emails
MARS_MAIL_FROM="$(basename $0)@$(hostname)"


# ---------- Subsection build mars module variables  --------------------------

# where we take build-snapshot-modules.sh and build-snapshot.sh from
MARS_BUILD_TOOLS_DIR=$WORKING_DIR/debpkg
MARS_BUILD_TOOLS_REPO=ssh://git@git.schlund.de/debian/mars.git
MARS_BUILD_TOOLS_BRANCH=build-snapshot
# fix part of snapshot version
BUILD_UI='ui60+0'
# grep patterns to find snapshot version in the output of build-snapshot.sh
BUILD_SNAPSHOT_PATTERN='^dpkg-source: info: building mars in mars_0.0.0.[0-9]\{8\}~snapshot[0-9]*-[0-9]*~'"$BUILD_UI"'.debian.tar.gz'
BUILD_SNAPSHOT_MODULES_PATTERN='^====Creating changelog for snapshot (debian version 0.0.[0-9]\{12\}~'"$BUILD_UI"')'
# where the packages reside on the build host
BUILD_HOST_HTTP_PATH='http://buildd-i386.schlund.de/~mini-buildd/rep'

# the distribution directory where the mars modules are built:
BUILD_DISTRI=squeeze-ui-experimental

# maxtime to wait for a package to be built [seconds]
BUILD_MAX_TIME=1800
# time between two polls [seconds]
BUILD_SLEEP=30


# ---------- Subsection git repository variables ------------------------------
# the mars repository.
# GIT_UPSTREAM and GIT_UPSTREAM_BRANCH are exported because they are used in
# build_snapshot.sh

export GIT_UPSTREAM=https://github.com/schoebel/mars.git
export GIT_UPSTREAM_BRANCH=${GIT_UPSTREAM_BRANCH:-master}
GIT_UPSTREAM_DIR=upstream

# the repository where the test suite resides (may coincide with GIT_UPSTREAM)
GIT_TEST_SUITE=https://github.com/fliepold/mars
GIT_TEST_SUITE_BRANCH=WIP-test_suite
GIT_TEST_SUITE_DIR=test_suite

trap myexit ERR INT

# ---------------- Section: functions -----------------------------------------
function usage
{
    echo "usage: $(basename $0) [-s] [-m]" >&2
    echo "      option -s: start a ssh-agent and add key file" >&2
    echo "      option -m: only build the module without installing it" >&2
    echo "      option -n: in case of failure notify recipients listed in MARS_MAIL_TO" >&2
    exit 1
}

rm_tmp_dir=1
function myexit
{
    local rc=$1 err_msg="$2"
    if [ -n  "$err_msg" ]; then
        echo "$err_msg" >&2
    fi
    if [ $rm_tmp_dir -eq 1 ]; then
        rm -rf $TMPDIR
    else
        echo saved tmpdir $TMPDIR >&2
    fi
    if [ $rc -ne 0 ]; then
        echo "callstack:" >&2
        print_callstack >&2
        if [ $notify_in_case_of_failure -eq 1 ]; then
            notify_email_recipients \
                "$(date): error $rc in $(basename $0), see logfile ($MARS_CRON_OUT)"
        fi
    fi
    exit $rc
}

function notify_email_recipients
{
    local msg="$1" to attach_opt
    if [ -n "$MARS_CRON_OUT" ] && [ -s "$MARS_CRON_OUT" ]; then
        attach_opt="-a $MARS_CRON_OUT"
    fi
    for to in ${MARS_MAIL_TO//,/ }; do
        sendEmail -m "$msg" -f "$MARS_MAIL_FROM" -t $to \
                  -u "failed mars tests $(date)" \
                  -s "$MARS_MAIL_SERVER_AND_PORT" $attach_opt
    done
}

function print_callstack
{
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
}

function checkout_build_tools
{
    echo "${FUNCNAME[0]} $*"
    local cmd="git clone -b $MARS_BUILD_TOOLS_BRANCH $MARS_BUILD_TOOLS_REPO $MARS_BUILD_TOOLS_DIR"
    rm -rf $MARS_BUILD_TOOLS_DIR || \
                                myexit 1 "cannot remove $MARS_BUILD_TOOLS_DIR"
    echo executing: $cmd ...
    $cmd || lib_exit 1
}

# ugly ... but working
# for $3 = build_snapshot:
#   extract package version (0.0.0.20140423~snapshot0655-1~ui60+0) from line
#   
#   dpkg-source: info: building mars in mars_0.0.0.20140423~snapshot0655-1~ui60+0.debian.tar.gz
#
# for $3 = build_snapshot_modules:
#   extract package version (0.0.201404240925~ui60+0) from line
#   
#   ====Creating changelog for snapshot (debian version 0.0.201404240925~ui60+0)
#
function get_package_version_from_file
{
    local logfile=$1 pattern="$2" pattern_type=$3 match_line rc match_count
    [ -s "$logfile" ] || myexit 1 "file $logfile not found or empty"
    match_count="$(grep "$pattern" $logfile | wc -l)" || myexit 1
    if [ $match_count -ne 1 ]; then
        rm_tmp_dir=0
        myexit 1 "pattern '$pattern' found $match_count ( != 1) times in $logfile"
    fi
    match_line="$(grep "$pattern" $logfile)"
    case $pattern_type in # (((
        build_snapshot)
                match_line="${match_line#*building mars in mars_}"
                match_line="${match_line%.debian.tar.gz}"
                ;;
        build_snapshot_modules)
                match_line="${match_line#*changelog for*(debian version }"
                match_line="${match_line%)*}"
                ;;
        *) myexit 1 "invalid pattern_type $pattern_type"
    esac
    echo "$match_line"
}

function wait_for_package_on_build_host
{
    echo "${FUNCNAME[0]} $*"
    local package_name="$1" waited=0
    local pwd=$(pwd) rc
    local url="$BUILD_HOST_HTTP_PATH/$BUILD_DISTRI/$package_name"
    cd $TMPDIR || myexit 1
    while true; do
        if wget "$url"; then
            break
        fi
        sleep $BUILD_SLEEP
        let waited+=$BUILD_SLEEP
        echo "waited $waited seconds for $url to appear"
        if [ $waited -eq $BUILD_MAX_TIME ]; then
            cd $pwd
            myexit 1 "maxwait exceeded"
        fi
    done
    cd $pwd
}

function get_kernel_releases_of_test_hosts
{
    echo "${FUNCNAME[0]} $*"
    local host
    for host in ${MARS_TEST_HOSTS[*]}; do
        kernel_release[$host]=$(ssh -i $MARS_SSH_KEYFILE \
                                root@$host "uname -r") || myexit 1
    done
    echo "found kernel releases:"
    echo "${!kernel_release[*]}"
    echo "${kernel_release[*]}"
}


# waits for e.g.
#
# http://buildd-i386.schlund.de/~mini-buildd/rep//squeeze-ui-experimental/mars-modules-2.6.32-openvz042stab084.25-dbg_0.0.0.20140423~snapshot0655+042stab084.25~ui60+1.20140218+0.0.201404230815~ui60+0_amd64.deb
#
# where
#
# kernel release  = 2.6.32-openvz042stab084.25
# package version = 0.0.201404230815"ui60+0
#
function wait_for_module_packages_for_all_kernel_releases
{
    echo "${FUNCNAME[0]} $*"
    local package_version="$1" release
    for release in ${kernel_release[*]}; do
        local lynx_out=$TMPDIR/lynx.out
        local waited=0
        local url="$BUILD_HOST_HTTP_PATH/$BUILD_DISTRI"
        local pattern_part_1="mars-modules-${release}-dbg_"
        local pattern_part_2=".*${package_version}"
        local pattern_part_3="_amd64.deb"
        local pattern="${pattern_part_1}${pattern_part_2}${pattern_part_3}"
        echo "waiting for module package $package_version, kernel_release $release"
        echo ":grep pattern:=:$pattern:"
        while true; do
            local match_count
            lynx -dump $url >$lynx_out || myexit 1
            match_count=$(grep "$pattern" $lynx_out | wc -l) || myexit 1
            if [ $match_count -eq 1 ]; then
                break
            elif [ $match_count -gt 1 ]; then
                rm_tmp_dir=0
                myexit 1 "pattern :$pattern: found $match_count (!= 1) times in $lynx_out"
            fi
            sleep $BUILD_SLEEP
            let waited+=$BUILD_SLEEP
            echo "waited $waited seconds for package to appear"
            if [ $waited -eq $BUILD_MAX_TIME ]; then
                cd $pwd
                myexit 1 "maxwait exceeded"
            fi
        done
        # the line found in $lynx_out looks like
        #
        #  999. http://buildd-i386.schlund.de/~mini-buildd/rep/squeeze-ui-experimental/mars-modules-2.6.32-openvz042stab084.25-dbg_0.0.0.20140424~snapshot1116+042stab084.25~ui60+1.20140218+0.0.201404241119~ui60+0_amd64.deb
        #
        # the package version to write to $out_file would be
        #
        # 0.0.0.20140424~snapshot1116+042stab084.25~ui60+1.20140218+0.0.201404241119~ui60+0
        #
        package_for_kernel[$release]=$(grep "$pattern" $lynx_out | \
            sed "s/.*${pattern_part_1}\(${pattern_part_2}\)${pattern_part_3}.*/\1/")
    done
    echo "package versions for releases:"
    echo ${!package_for_kernel[*]}
    echo ${package_for_kernel[*]}
}

function build_module
{
    echo "${FUNCNAME[0]} $*"
    local cmd_prefix rc logfile package_version
    for cmd_prefix in build-snapshot build-snapshot-modules; do
        local cmd
        cmd="$MARS_BUILD_TOOLS_DIR/$cmd_prefix.sh"
        logfile=$TMPDIR/$cmd_prefix.log
        echo "executing: $cmd >$logfile"
        $cmd 2>&1 | tee $logfile
        rc=${PIPESTATUS[0]}
        if [ $rc -ne 0 ]; then
            rm_tmp_dir=0
            myexit $rc
        fi
        case $cmd_prefix in # (((
            build-snapshot)
                package_version="$(get_package_version_from_file \
                                   $logfile \
                                   "$BUILD_SNAPSHOT_PATTERN" \
                                   "build_snapshot" \
                                  )" || myexit 1
                wait_for_package_on_build_host \
                                        "mars-source_${package_version}_all.deb"
                ;;
            build-snapshot-modules)
                package_version="$(get_package_version_from_file \
                                   $logfile \
                                   "$BUILD_SNAPSHOT_MODULES_PATTERN" \
                                   "build_snapshot_modules" \
                                  )" || myexit 1
                wait_for_module_packages_for_all_kernel_releases \
                                                        "$package_version"
                ;;
            *) myexit 1 "invalid cmd_prefix $cmd_prefix"
                ;;
        esac
    done
}

function install_module_on_hosts
{
    echo "${FUNCNAME[0]} $*"
    local host
    for host in ${MARS_TEST_HOSTS[*]}; do
        local pv=${package_for_kernel[${kernel_release[$host]}]}
        echo aptitude update on $host
        ssh -i $MARS_SSH_KEYFILE root@$host 'aptitude update' || myexit 1
        echo "installing mars module ($pv) on $host"
        ssh -i $MARS_SSH_KEYFILE root@$host \
           'aptitude install -y mars-modules-$(uname -r)='"$pv"'' || myexit 1
    done
}

function clone_repo
{
    echo "${FUNCNAME[0]} $*"
    local repo=$1 repo_dir=$2 checkout_tag=$3
    local pwd=$(pwd)
    cd $TMPDIR || myexit 1
    echo "executing git clone $repo $repo_dir"
    git clone $repo $repo_dir || myexit 1
    cd $repo_dir || myexit 1
    git checkout $checkout_tag || myexit 1
    cd $pwd
}

function check_installed_module_version_against_upstream_repo
{
    echo "${FUNCNAME[0]} $*"
    local pwd=$(pwd) host
    local last_commit_repo

    clone_repo $GIT_UPSTREAM $GIT_UPSTREAM_DIR $GIT_UPSTREAM_BRANCH

    cd $TMPDIR/$GIT_UPSTREAM_DIR || myexit 1
    last_commit_repo=$(git log -n1 --pretty=oneline $GIT_UPSTREAM_BRANCH) || \
                                                                        myexit 1
    echo "last commit of branch $GIT_UPSTREAM_BRANCH: $last_commit_repo"
    for host in ${MARS_TEST_HOSTS[*]}; do
        local modinfo_out sha commit_to_sha
        modinfo_out="$(ssh -i $MARS_SSH_KEYFILE root@$host modinfo mars)" || \
                                                                        myexit 1
        # modinfo_out looks like
        #
        # filename:       /lib/modules/2.6.32-op...
        # debug:          production
        # license:        GPL
        # version:        0.1stable02-2cd47f4 (mini-buildd@ 2014-04-10 09:14:44)
        # author:         Thomas Schoebel-Theuer <tst@1und1.de>
        # ...
        # we need the sha:

        sha=${modinfo_out#*version: }
        sha=${sha#*-}
        sha=${sha%% *}
        echo sha of module mars on $host: $sha
        commit_to_sha=$(git log -n1 --pretty=oneline $sha) || myexit 1
        if [ "$last_commit_repo" != "$commit_to_sha" ]; then
            echo "last commit repo: $last_commit_repo != $commit_to_sha (commit to sha $sha of module mars on $host" >&2
            myexit 1
        fi
    done
    cd $pwd
}

function run_tests
{
    echo "${FUNCNAME[0]} $*"
    local pwd=$(pwd) i logfile

    rm -rf $TMPDIR/* || myexit 1
    clone_repo $GIT_TEST_SUITE $GIT_TEST_SUITE_DIR $GIT_TEST_SUITE_BRANCH 

    cd $TMPDIR/$GIT_TEST_SUITE_DIR
    for i in ${!MARS_TEST_HOSTS[*]}; do
        if [ $(($i % 2)) -eq 1 ]; then
            local cmd
            export MARS_INITIAL_PRIMARY_HOST=${MARS_TEST_HOSTS[$(($i - 1))]}
            export MARS_INITIAL_SECONDARY_HOST=${MARS_TEST_HOSTS[$i]}
            logfile=$LOGFILE_DIR/test-$MARS_INITIAL_PRIMARY_HOST-log.$(date +'%Y%m%d%H%M%S')
            export MARS_TEST_LOGFILE=$logfile
            cmd="$(pwd)/test_suite/mars/mars_test_cronjob.sh $(pwd)/test_suite $(pwd)/test_suite/mars"
            echo "$(date): starting $cmd &>$logfile on hosts $MARS_INITIAL_PRIMARY_HOST, $MARS_INITIAL_SECONDARY_HOST"
            $cmd &>$logfile &
            sleep 2
        fi
    done
    cd $pwd
}

# ---------------- Section: options --------------------------------------------

OPTSTR="nms"
add_ssh_key=0
build_without_install=0
notify_in_case_of_failure=0

while getopts "$OPTSTR" opt; do
    case $opt in # ((
        s) add_ssh_key=1
            ;;
        m) build_without_install=1
            ;;
        n) notify_in_case_of_failure=1
            ;;
        *) usage
            ;;
    esac
done

# ---------------- Section: main -----------------------------------------------

if [ $add_ssh_key -eq 1 ]; then
    echo "adding $MARS_SSH_KEYFILE to ssh-agent"
    eval $(ssh-agent) || myexit 1
    ssh-add $MARS_SSH_KEYFILE || myexit 1
fi

TMPDIR=$(mktemp -d) || myexit 1
cd $WORKING_DIR || myexit 1
if [ ! -d $LOGFILE_DIR ]; then
    mkdir $LOGFILE_DIR || myexit 1
fi

# host indexed array containing all different kernel releases of the test hosts
declare -A -g kernel_release

# kernel release indexed array containing the package version for the release
# the package version of mars-modules to install for that kernel
declare -A -g package_for_kernel

get_kernel_releases_of_test_hosts
checkout_build_tools
build_module
if [ $build_without_install -eq 1 ]; then
    echo "built module versions:"
    echo ${!package_for_kernel[*]}
    echo ${package_for_kernel[*]}
    myexit 0
fi
install_module_on_hosts
check_installed_module_version_against_upstream_repo
rm_tmp_dir=0
run_tests

myexit 0
