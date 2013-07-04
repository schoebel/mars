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

function file_handling_get_file_length
{
    local host=$1 logfile=$2
    local length
    length=$(lib_remote_idfile $host "ls -l $logfile") || lib_exit 1
    # geting length out of ls -l output (e.g.:
    # -rw-rw-r-- 1 fl fl 11 Jun 11 17:06 /home/fl/tmp/f1
    # )
    length=${length#* * * * }
    length=${length%% *}
    expr "${length}" : '^[0-9][0-9]*$' >/dev/null || \
        lib_exit 1 "invalid length $length for $host:$logfile"
    echo $length
}

function file_handling_check_equality_of_file_lengths
{
    local file=$1 host_1=$2 host_2=$3 file_length_host_2=$4 
    local file_length_host_1
    file_length_host_1=$(file_handling_get_file_length $host_1 $file) || \
                                                                    lib_exit 1
    if [ $file_length_host_1 -ne $file_length_host_2 ]; then
        lib_exit 1 "length $host_1:$file = $file_length_host_1 != $file_length_host_2 = length $host_2:$file"
    fi
}

    
