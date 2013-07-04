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

function checkout_mars_run
{
    local dir

    declare -A checkout_dirs
    declare -A checkout_branches

    checkout_branches["$checkout_mars_src_directory"]="$checkout_mars_git_branch"
    checkout_branches["$checkout_mars_kernel_src_directory"]="$checkout_mars_kernel_git_branch"
    checkout_branches["$checkout_mars_contrib_src_directory"]="$checkout_mars_contrib_git_branch"
 
    for dir in ${!checkout_branches[@]};do
        if [ ! -d "$dir" ];then
            echo "  $BASH_SOURCE:$LINENO: checkout directory $dir not found"
            exit 1
        fi
    done

    if (( checkout_mars_fetch_git_repository )); then 
        echo "  $BASH_SOURCE:$LINENO: git fetch not implemented yet" >&2
        exit 1
    fi
    local pwd=$(pwd) br
    for dir in ${!checkout_branches[@]}; do
        br=${checkout_branches["$dir"]}
        lib_vmsg "  checking out branch $br in $dir"
        cd $dir || lib_exit 1
        pwd
        if git status | egrep 'modified:|new file' ; then
            local stash_name="stash.$(date +'%Y%m%d%H%M')"
            lib_vmsg "  saving to stash $stash_name"
            git stash save $stash_name
        fi
        git fetch origin || lib_exit 1
        git checkout $br || lib_exit 1
        git rebase remotes/origin/$br || lib_exit 1
    done
}

