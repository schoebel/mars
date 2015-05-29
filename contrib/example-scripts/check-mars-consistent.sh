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
#
# check_mars_consistent.sh
#
# This script is NOT for deciding whether a switchover is
# possible.
#
# It tests a much simpler condition: whether a _potential_ target
# of a switchover is principally / _statically usable_ for switchover
# at all. 
#
# This is a true subset of the conditions checked by check_mars_switchable.sh.
#
# NOTICE: this does to take split brain into account. It cannot tell you
# which side is the "correct" one.
#
# Please use check_mars_switchable.sh for deciding whether an actual
# switchover should be started.

# Allow overrides of default values by external config file
for path in {.,$HOME,/etc/defaults}/check-mars-consistent.conf; do
    [[ -r $path ]] && . $path
done

# This script works on a single resource, or on "all".
# When no argument is given, treat as "all".

if [[ "$1" = "all" ]] || [[ "$1" = "" ]] ; then
    rc=0
    for resource in $(marsadm view-my-resources 2> /dev/null); do
	$0 $resource || (( rc++ ))
    done
    exit $rc
fi

resource="$1"


# Check whether the resource is already Primary.
# It does not make any sense to switchover to itself.
# But anyway, we simply say "OK", because the primary side
# is always consistent by _definition_.

if (( $(marsadm view-is-primary $resource 2> /dev/null) > 0 )); then
    echo "OK: resource '$resource' is consistent at generic mars level."
    exit 0
fi

# Check whether sync has finished

if (( $(marsadm view-sync-rest $resource 2> /dev/null) > 0 )); then
    echo "ERROR: resource '$resource' is inconsistent because it has not (yet) reached sync"
    exit 1
fi


# Check whether consistency has been violated

if (( $(marsadm view-is-consistent $resource 2> /dev/null) < 1 )); then
    echo "ERROR: resource '$resource' is not (yet) consistent"
    exit 1
fi

# Finally: no errors found

echo "OK: resource '$resource' is consistent at generic mars level."
exit 0
