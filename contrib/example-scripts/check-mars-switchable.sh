#!/bin/bash
#
# This file is part of MARS project: http://schoebel.github.io/mars/
#
# Copyright (C) 2015 Thomas Schoebel-Theuer
# Copyright (C) 2015 1&1 Internet AG
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

# TST summer 2015 lab prototype

const_fetch_warn=${const_fetch_warn:-20000} # KiB
const_replay_warn=${const_replay_warn:-500000} # KiB

# Allow overrides of default values by external config file
for path in {.,$HOME,/etc/defaults}/check-mars-switchable.conf; do
    [[ -r $path ]] && . $path
done

# Global precondition: the mars kernel module must be loaded.

if ! [[ -d /proc/sys/mars ]]; then
    echo "ERROR: mars kernel module is not loaded"
    exit 1
fi

# This script works on a single resource, or on "all".
# When no argument is given, treat as "all".

if [[ "$1" = "all" ]] || [[ "$1" = "" ]] ; then
    rc=0
    for resource in $(marsadm view-my-resources); do
	$0 $resource || (( rc++ ))
    done
    exit $rc
fi

resource="$1"


# Check whether the resource is attached.

if (( $(marsadm view-is-attach $resource) < 1 )); then
    echo "ERROR: resource '$resource' is not attached"
    exit 1
fi

# Check whether the resource is already Primary.
# In this case, we simply say "OK", because it will do no harm
# if you switch something to Primary which is already Primary.
# Alternatively, you may place an error here.

if (( $(marsadm view-is-primary $resource) > 0 )); then
    echo "OK: resource '$resource' is already Primary. Nothing to do."
    exit 0
fi

# Check whether sync has finished

if (( $(marsadm view-sync-rest $resource) > 0 )); then
    echo "ERROR: resource '$resource' has not reached sync"
    exit 1
fi


# Check whether consistency has been violated

if (( $(marsadm view-is-consistent $resource) < 1 )); then
    echo "ERROR: resource '$resource' is not (yet) consistent"
    exit 1
fi

# Check whether the current primary can be reached over network.
# We issue a warning only.

if (( $(marsadm view-is-alive $resource) < 1 )); then
    echo "WARNING: the current Primary '$(marsadm view-get-primary $resource)' of resource '$resource' cannot be reached currently. You may need --force if you really want to switch anyway."
fi


# Check split brain.
# We issue a warning only.

if (( $(marsadm view-is-split-brain $resource) > 0 )); then
    echo "WARNING: resource '$resource' is in split brain mode. Switching via --force should be possible, but be sure to switch to the correct side."
fi

# Check fetch and replay margins.
# We issue a warning only.

for mode in fetch replay; do
    limit=$(eval echo \$const_${mode}_warn)
    # disable the check if the limit is zero
    (( limit <= 0 )) && continue
    # convert units from bytes to KiB
    value=$(( $(marsadm view-$mode-rest $resource) / 1024 ))
    if (( value > limit )); then
	echo "WARNING: resource '$resource' has $mode lagbehind: $value > $limit KiB"
    fi
done

# Finally: no errors found

echo "OK: nothing speaks against switching resource '$resource' at generic mars level."
exit 0
