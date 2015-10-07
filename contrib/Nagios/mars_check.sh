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


#
# Nagios check, respecting debian package settings
#
# TST spring 2015 lab prototype
#
# Verbose mode and options / help is not yet supported.

#set -e
orig_vars="$(set | grep '^[_A-Za-z0-9]\+=' | cut -d= -f1)"

# Config file for defaults.
# May be used for hard override of the following definitions.
default_file="${default_file:-/etc/default/mars}"

# Defaults for configuration variables
service="${service:-MARS}"
check_enable=${check_enable:-1}
alive_window=${alive_window:-120} # seconds
responsive_window=${responsive_window:-600} # seconds
class_mode=${class_mode:-1}
warnings=${warnings:-0}
simulate=${simulate:-0}
verbose=${verbose:-0}
help=${help:-0}

mars_dir="${mars_dir:-/mars}"
config_dir="${config_dir:-/etc/mars}"
config_file="${config_file:-mars.rules}"
statusfile_dir="${statusfile_dir:-/var/cache/mars}"
status_last="${status_last:-$statusfile_dir/last.status}"
status_medium="${status_medium:-$statusfile_dir/medium.status}"
status_longterm="${status_long:-$statusfile_dir/longterm.status}"
window_medium=${window_medium:-3600}
window_longterm=${window_longterm:-$(( 3600 * 24 ))}

# Enable this script by default
ENABLED="true"

param_vars="$(set | grep '^[_A-Za-z0-9]\+=' | cut -d= -f1)"

# Derived from the defaults
file_list="./$config_file $config_dir/$config_file"

# Nagios Exit Codes
OK=0
WARNING=1
CRITICAL=2
UNKNOWN=3

function abort
{
    local msg="$1"
    echo "$service Unknown: $msg"
    exit $UNKNOWN
}

function source_when_possible
{
    local file="$1"
    local type="$2"

    if [[ -r "$file" ]]; then
	. "$file" || abort "$type file $file is not parsable"
    fi
}

source_when_possible "$default_file" "config"

# Allow forceful override of any _known_ variable at the command line
for i; do
    if [[ "$i" =~ ^--[-_A-Za-z0-9]+$ ]]; then
	param="${i#--}"
	var="${param//-/_}"
        [[ "$(eval "echo \"\$$var\"")" = "" ]] && abort "Variable '$var' is unknown"
	eval "$var=1"
    elif [[ "$i" =~ ^--[-_A-Za-z0-9]+= ]]; then
	param="${i#--}"
	var="${param%%=*}"
	var="${var//-/_}"
	val="${param#*=}"
        [[ "$(eval "echo \"\$$var\"")" = "" ]] && abort "Variable '$var' is unknown"
	eval "$var=$val"
    elif [[ "$i" =~ ^-h$ ]]; then
	help=1
    elif [[ "$i" =~ ^-v$ ]]; then
	(( verbose++ ))
    else
	abort "bad parameter syntax '$i'"
    fi
done

# Almost silently exit if not enabled
if (( !check_enable)) || [[ "$ENABLED" != "true" ]] && (( !help )); then
    echo "${service}_IS_DISABLED OK"
    exit $OK
fi

########################
# Prepare Variables

var_list="ListOfPrimary ListOfNotYetPrimary ListOfRemainsPrimary ListOfSecondary ListOfAny"
val_list="ElapsedLast ElapsedMedium ElapsedLongterm ModuleLoaded Responsive SpacePercent SpaceRest"
array_list="SplitBrain Designated Alive AliveAge Sync Fetch Replay SyncRest FetchRest ReplayRest Emergency"

start_vars="$(set | grep '^[_A-Za-z0-9]\+=' | cut -d= -f1)"

for i in $var_list $val_list; do
    eval "$i=''"
    for age in Last Medium Longterm; do
	eval "$age$i=''"
    done
done

for i in $array_list; do
    eval "declare -A $i"
    for age in Last Medium Longterm; do
	eval "declare -A $age$i"
    done
done

basic_vars="$(set | grep '^[_A-Za-z0-9]\+=' | cut -d= -f1)"

########################
# Help text

if (( help )); then
    all_vars="$(set | grep '^[_A-Za-z0-9]\+=' | cut -d= -f1 | sort)"
    cat<<EOF
Nagios-compatible plugin for service $service

Usage: $0 [-h] {-v} {--<switch>} {--<var>=<value>}

The following parameter variables can be either passed by the
environment, or used for hard overrinding on the command line:

$(
    declare -A orig
    for i in $orig_vars; do
	orig[$i]=1
    done
    declare -A param
    for i in $param_vars; do
	param[$i]=1
    done
    for i in $all_vars; do
	[[ "$i" =~ _vars$ ]] && continue
	if (( param[$i] && !orig[$i] )); then
	    echo "$i=$(eval "echo \${$i}")"
	fi
    done
)

The following CamelCase basic variables may be used in one of the
rules files $file_list:

$(
    declare -A start
    for i in $start_vars; do
	start[$i]=1
    done
    declare -A basic
    for i in $basic_vars; do
	basic[$i]=1
    done
    for i in $all_vars; do
	[[ "$i" =~ _vars$ ]] && continue
	if (( basic[$i] && !start[$i] )); then
	    keys="$(eval echo "\${!$i[@]}")"
	    if [[ "$keys" != "0" ]]; then
		echo "${i}[\$res]"
	    else
		echo "$i"
	    fi
	fi
    done
)
EOF
    exit 0
fi

########################
# Read in old status files

source_when_possible "$status_last" "last status"
source_when_possible "$status_medium" "medium-term status"
source_when_possible "$status_longterm" "longterm status"

marsadm=${marsadm:-$(which marsadm)}
# exit if marsadm is not found
command -v $marsadm > /dev/null || abort "Command marsadm '$marsadm' is not installed"

gmacro=""
########################
# get Global variables

ElapsedLast=$(( $(date +%s) - $(stat --printf="%Y" $status_last 2> /dev/null || echo "0") ))
ElapsedMedium=$(( $(date +%s) - $(stat --printf="%Y" $status_medium 2> /dev/null || echo "0") ))
ElapsedLongterm=$(( $(date +%s) - $(stat --printf="%Y" $status_longterm 2> /dev/null || echo "0") ))

ModuleLoaded="$( [[ -d /prco/sys/mars ]]; echo $? )"

gmacro+="Responsive=\"%is-alive{%{host}}\"\n"

SpacePercent="$(df $mars_dir | grep -o "[0-9]\%" | tail -1 | sed 's/\%//g' 2> /dev/null)"

gmacro+="SpaceRest=\"%rest-space{}\"\n"

data="$($marsadm --macro="$gmacro" --window=$responsive_window view)"
#echo "$data"
eval "$data"

# get a list of Primary and Secondary resource names
# don't run the while loop in a subshell, use the main shell
while read dashes txt res; do
    read role
    eval "ListOf$role+=' $res'"
    eval "ListOfAny+=' $res'"
done <<EOF 2> /dev/null
$($marsadm view-role all 2> /dev/null)
EOF

########################
# get Resource variables

declare -A macro
for i in $ListOfAny; do
    #SplitBrain[$i]="$($marsadm view-is-split-brain $i 2> /dev/null)"
    macro[$i]+="SplitBrain[$i]=\"%is-split-brain{}\"\n"
    #Emergency[$i]="$($marsadm view-is-emergency $i < /dev/null 2> /dev/null)"
    macro[$i]+="Emergency[$i]=\"%is-emergency{}\"\n"
done

for i in $ListOfPrimary; do
    : #echo "Pri '$i'"
done

for i in $ListOfSecondary; do
    #Designated[$i]="$($marsadm view-get-primary $i 2> /dev/null)"
    macro[$i]+="Designated[$i]=\"%get-primary{}\"\n"
    #Alive[$i]="$($marsadm --macro="%is-alive{${Designated[$i]}}" --window=$alive_window view $i 2> /dev/null)"
    macro[$i]+="Alive[$i]=\"%is-alive{${Designated[$i]}}\"\n"
    #AliveAge[$i]="$($marsadm view-alive-age $i 2> /dev/null)"
    macro[$i]+="AliveAge[$i]=\"%alive-age{}\"\n"
    #Sync[$i]="$($marsadm view-todo-sync $i 2> /dev/null)"
    macro[$i]+="Sync[$i]=\"%todo-sync{}\"\n"
    #Fetch[$i]="$($marsadm view-todo-fetch $i 2> /dev/null)"
    macro[$i]+="Fetch[$i]=\"%todo-fetch{}\"\n"
    #Replay[$i]="$($marsadm view-todo-replay $i 2> /dev/null)"
    macro[$i]+="Replay[$i]=\"%todo-replay{}\"\n"
    #SyncRest[$i]="$($marsadm view-sync-rest $i 2> /dev/null)"
    macro[$i]+="SyncRest[$i]=\"%sync-rest{}\"\n"
    #FetchRest[$i]="$($marsadm view-fetch-rest $i 2> /dev/null)"
    macro[$i]+="FetchRest[$i]=\"%fetch-rest{}\"\n"
    #ReplayRest[$i]="$($marsadm view-replay-rest $i 2> /dev/null)"
    macro[$i]+="ReplayRest[$i]=\"%replay-rest{}\"\n"
done

for i in ${!macro[*]}; do
    data="$($marsadm --macro="${macro[$i]}" --window=$alive_window view $i)"
    #echo "$data"
    eval "$data";
done

########################
# compute Delta variables (when possible)

for i in $val_list; do
    for age in Last Medium Longterm; do
	if [[ "$(eval echo "\${$age$i}")" != "" ]]; then
	    declare Delta$age$i
	    eval "Delta$age$i=$(( $(eval echo "\${$i}") - $(eval echo "\${$age$i}") ))"
	    declare Rate$age$i
	    eval "Rate$age$i=$(( $(eval echo "\${Delta$age$i}") * 60 / Elapsed${age} ))"
	fi
    done
done
for i in $array_list; do
    for j in $(eval echo "\${!$i[*]}"); do
	for age in Last Medium Longterm; do
	    if [[ "$(eval echo "\${$age$i[$j]}")" != "" ]]; then
		declare -A Delta$age$i[$j]
		eval "Delta$age$i[$j]=$(( $(eval echo "\${$i[$j]}") - $(eval echo "\${$age$i[$j]}") ))"
		declare -A Rate$age$i[$j]
		eval "Rate$age$i[$j]=$(( $(eval echo "\${Delta$age$i[$j]}") * 60 / Elapsed${age} ))"
	    fi
	done
    done
done

########################
# Write out new status file

mkdir -p "$statusfile_dir"
(
    for i in $var_list $val_list; do
	echo "Last$i='$(eval echo "\${$i}")'"
    done
    
    for i in $array_list; do
	for j in $(eval echo "\${!$i[*]}"); do
	    echo "Last$i[$j]='$(eval echo "\${$i[$j]}")'"
	done
    done
) > "${status_last}.tmp" && \
    mv "${status_last}.tmp" "${status_last}" && \
    if ! [[ -r $status_medium.tmp ]] || (( $(stat --printf="%Y" $status_medium.tmp) < $(stat --printf="%Y" $status_last) - ( $window_medium / 2 ) )); then
    mv -f $status_medium.tmp $status_medium 2> /dev/null || true
    sed 's/^Last/Medium/' < $status_last > $status_medium.tmp2 && \
	mv $status_medium.tmp2 $status_medium.tmp
fi &&\
    if ! [[ -r $status_longterm.tmp ]] || (( $(stat --printf="%Y" $status_longterm.tmp) < $(stat --printf="%Y" $status_last) - ( $window_longterm / 2 ) )); then
    mv -f $status_longterm.tmp $status_longterm 2> /dev/null || true
    sed 's/^Last/Longterm/' < $status_last > $status_longterm.tmp2 && \
	mv $status_longterm.tmp2 $status_longterm.tmp
fi

########################
# Output Handling

code_max=0

# this can be called multiple times.
# it remembers the maximum error level in $code_max
function do_check
{
    local class="$1"
    local key="$2"

    local file
    local rule_var
    local rule_op
    local rule_val
    local rule_txt
    local found_count=0
    local matches=0

    for file in $file_list; do
	if [[ -r "$file" ]]; then
	    while read rule_class rule_var rule_op rule_val rule_txt; do
		if [[ "$rule_var" = "$key" ]]; then
		    (( ++found_count ))
		    (( rule_class != class && class_mode )) && continue
		    local keys="$(eval echo "\${!$rule_var[@]}")"
		    if [[ "$keys" != "" ]] && [[ "$keys" != "0" ]]; then
			local res
			for res in $keys; do
			    if [[ "$(eval echo "\${$rule_var[$res]}")" != "" ]]; then
				while (( $rule_var[$res] $rule_op $rule_val || simulate )); do
				    (( ++matches ))
				    if [[ "$rule_txt" =~ "&&" ]]; then
					read dummy rule_var rule_op rule_val rule_txt <<< "$rule_txt"
				    else
					_out_txt "$rule_txt" "$res"
					break
				    fi
				done
			    else
				(( warnings )) && echo "Undefined variable '$rule_var[$res]'" >> /dev/stderr
			    fi
			done
		    else
			if [[ "$(eval echo "\${$rule_var}")" != "" ]]; then
			    while (( $rule_var $rule_op $rule_val || simulate )); do
				(( ++matches ))
				if [[ "$rule_txt" =~ "&&" ]]; then
				    read dummy rule_var rule_op rule_val rule_txt <<< "$rule_txt"
				else
				    _out_txt "$rule_txt" "UNDEF"
				    break
				fi
			    done
			else
			    (( warnings )) && echo "Undefined variable '$rule_var'" >> /dev/stderr
			fi
		    fi
		fi
	    done <<EOF
$(grep -v '^#' $file | grep -v '^\s*$')
EOF
	fi
    done
    if (( warnings && !found_count )); then
	echo "Cannot find key '$key' in $config_file $config_dir/$config_file" >> /dev/stderr
    fi
    return 0
}

function _out_txt
{
    local txt="$1"
    local res="$2"

    txt="$(echo "$txt" | sed 's/\${/\\\${/g')"
    # eval down (fixedpoint iteration)
    local old=""
    while [[ "$txt" != "$old" ]]; do
	old="$txt"
	txt="$(eval echo "$txt")"
    done
    echo "$service $txt"

    local this_code=0
    echo "$txt" | grep -i -q "WARNING" && this_code=1
    echo "$txt" | grep -i -q "CRITICAL" && this_code=2
    (( this_code > code_max )) && code_max=$this_code
    return 0
}

########################
# Main program

class_list="$(cat $file_list 2>/dev/null | grep -v '^#' | grep -v '^\s*$' | cut -d" " -f1 | sort -n -u)"

for class in $class_list; do
    ########################
    # Global checks

    do_check "$class" ModuleLoaded
    do_check "$class" Responsive
    do_check "$class" SpacePercent
    do_check "$class" SpaceRest

    ########################
    # Resource checks

    do_check "$class" Alive
    do_check "$class" AliveAge
    do_check "$class" Emergency
    do_check "$class" SplitBrain
    for i in $ListOfSecondary; do
	do_check "$class" Sync
	do_check "$class" Fetch
	do_check "$class" Replay
	do_check "$class" SyncRest
	do_check "$class" FetchRest
	do_check "$class" ReplayRest
	for age in Last Medium Longterm; do
	    do_check "$class" Delta${age}SyncRest
	    do_check "$class" Delta${age}FetchRest
	    do_check "$class" Delta${age}ReplayRest
	done
    done
    (( !class_mode )) && break
    (( class > 0 && code_max > 0 )) && break
done

if (( !code_max )); then
    echo "$service OK"
fi
exit $code_max
