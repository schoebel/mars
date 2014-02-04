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

function run_colors
{
    echo entering ${FUNCNAME[0]}
    # to show the use of main_error_recovery_functions (see also README)
    # in case of premature return we want to call colors_restore_something 
    main_error_recovery_functions["colors_restore_something"]="param1 param2"
    echo my_color = $colors_my_color
    case "$colors_my_color" in # ((
        red|green|blue):;;
        *) lib_exit 1 "no valid color"
    esac
    main_error_recovery_functions["colors_restore_something"]=
    echo leaving ${FUNCNAME[0]}
}

function colors_restore_something
{
    echo entering ${FUNCNAME[0]}
    echo "parameter 1 = $1, parameter 2 = $2"
    echo leaving ${FUNCNAME[0]}
}

