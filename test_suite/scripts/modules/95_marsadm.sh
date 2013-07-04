#!/bin/sh

function marsadm_do_cmd
{
    local host=$1 cmd="$2" cmd_args="$3" rc
    local marscmd="marsadm --timeout=$marsadm_timeout $cmd $cmd_args"
    lib_vmsg "  executing $marscmd on $host"
    lib_remote_idfile $host $marscmd
    rc=$?
    if [ $rc -ne 0 ]; then
        return $rc
    fi
    # replace - with _ and remove everything after last blank 
    local post_condition_check=${cmd//-/_}
    post_condition_check=${post_condition_check%% *}
    post_condition_check=marsadm_check_post_condition_${post_condition_check}
    case "$cmd" in # ((
        resize*|pause-sync*|primary*) $post_condition_check $host "$cmd_args"
             ;;
        *) :
        ;;
    esac
}

function marsadm_get_role
{
    local host=$1 res=$2 output
    output=$(lib_remote_idfile $host "marsadm role $res") || lib_exit 1
    expr "$output" : 'I am actually \([^ ][^ ]*\).*'
}

function marsadm_check_post_condition_primary
{
    local host=$1 cmd_args=("$2")
    local res=${cmd_args[0]}
    local role
    role=$(marsadm_get_role $host $res) || lib_exit 1
    if [ "$role" != "primary" ]; then
        lib_exit 1 "role expected = primary != $role = role found"
    fi
}

function marsadm_check_post_condition_pause_sync
{
    local host=$1 cmd_args=("$2")
    local res=${cmd_args[0]}
    lib_linktree_check_link_int_value $host $res "sync" 0 1
}

function marsadm_check_post_condition_resize
{
    local host=$1 cmd_args=($2)
    local res=${cmd_args[0]} size=${cmd_args[1]}
    lib_linktree_check_link_int_value $host $res "size" \
                                      $size 1000000000
    lib_linktree_check_link_int_value $host $res "syncstatus" \
                                      $size 1000000000
}


function marsadm_get_logfilename_prefix
{
    local res=$1
    local resource_dir=$(lib_linktree_get_resource_dir $res)
    echo "$resource_dir/log-"
}

function marsadm_get_logfilename_postfix
{
    local primary_host=$1 
    echo "-$primary_host"
}


function marsadm_get_last_logfile
{
    [ $# -eq 3 ] || lib_exit 1 "wrong number $# of arguments (args = $*)"
    local host=$1 res=$2 primary_host=$3
    local prefix=$(marsadm_get_logfilename_prefix $res)
    local postfix=$(marsadm_get_logfilename_postfix $primary_host)
    local all_logfiles
    all_logfiles=($(lib_remote_idfile $host "ls -1 ${prefix}*${postfix}")) \
                                                            || lib_exit 1
    echo ${all_logfiles[$((${#all_logfiles[*]} - 1))]}
}

function marsadm_pause_cmd
{

    local cmd=$1 host=$2 res=$3
    local marsadm_cmd repl_state
    case $cmd in
        apply) marsadm_cmd="pause-replay"
               repl_state='...-.'
               ;;
        fetch) marsadm_cmd="disconnect"
               repl_state='..-..'
               ;;
            *) lib_exit 1 "wrong cmd $cmd"
               ;;
    esac

    marsadm_do_cmd $host "$marsadm_cmd" $res || lib_exit 1
    marsview_check $host $res "repl" "$repl_state" || lib_exit 1
}

function marsadm_set_proc_sys_mars_parameter
{
    local host=$1 param="$2" param_value="$3"
    local dir=/proc/sys/mars
    lib_vmsg "  setting $dir/$param to $param_value on $host"
    lib_remote_idfile $host "echo $param_value >$dir/$param" || lib_exit 1
}

function marsadm_check_warn_file_and_disk_state
{
    local host=$1 res=$2 situation="$3"
    case $situation in # ((
        apply_stopped_after_disconnect)
            local link_value not_applied restlen_in_warn_file
            local warn_file="$(lib_linktree_get_resource_dir $res)/2.warn.status"
            local link=$(lib_linktree_get_res_host_linkname $host $res "replay")
            link_value=$(lib_remote_idfile $host "readlink $link") || lib_exit 1

            # extract last int from log-000000001-istore-test-bs7,317023740,2564
            not_applied=${link_value##*,}
            if ! expr "$not_applied" : '^[0-9][0-9]*$' >/dev/null; then
                lib_exit 1 "cannot determine last int in $link_value"
            fi
            lib_vmsg "  number of bytes not applied: $not_applied"
            if [ $not_applied -eq 0 ];then
                marsview_check $host $res "disk" "Uptodate" || lib_exit 1
                return 0
            fi
            lib_vmsg "  checking file $warn_file on $host"
            restlen_in_warn_file=$(marsadm_get_number_bytes_unreadable_logend \
                                   $host $res $warn_file) || lib_exit 1
            if [ $restlen_in_warn_file -ne $not_applied ]; then
                lib_exit 1 "not applied = $not_applied != $restlen_in_warn_file = restlen in $warn_file"
            fi
            marsview_check $host $res "disk" "Outdated\[FA\]" || lib_exit 1
            ;;
        *) lib_exit 1 "invalid situation $situation"
            ;;
    esac
}

function marsadm_get_number_bytes_unreadable_logend
{
    local host=$1 res=$2 warn_file=$3
    local restlen grep_out
    lib_remote_idfile $host "test -f $warn_file" || lib_exit 1
    grep_out=$(lib_remote_idfile $host \
              "grep 'mars_logger.*restlen =.*truncated' $warn_file | tail -1")\
                                                            || lib_exit 1
    # grep_out = ... but available data restlen = 2564. Was the ...
    restlen=${grep_out##*available data restlen = }
    restlen=${restlen%%.*}
    if ! expr "$restlen" : '^[0-9][0-9]*$' >/dev/null; then
        lib_exit 1 "cannot determine restlen in $grep_out"
    fi
    echo $restlen
}
