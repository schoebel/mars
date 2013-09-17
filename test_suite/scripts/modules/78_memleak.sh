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

## This test provoked a memleak error in mars versions up to light0.1beta0.12

function memleak_run
{
    local primary_host=${main_host_list[0]}
    local res=${resource_name_list[0]}
    local data_dev=$(resource_get_data_device $res)
    local cmd='dd if=/dev/zero of='"$data_dev"' bs=4096 count=1000000 & sleep 1;  kill -9  $(jobs -p); maxcount=20; count=0; while test $count -lt $maxcount && ! marsadm secondary '"$res"' ; do date; echo $count; sleep 1; let count+=1; done'
    resource_create $primary_host $res
    lib_vmsg "  starting on $primary_host: $cmd"
    lib_remote_idfile $primary_host $cmd
    # wait a little for an error file to appear
    sleep 3
}

