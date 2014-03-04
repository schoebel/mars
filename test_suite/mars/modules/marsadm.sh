#!/bin/sh

function marsadm_do_cmd
{
    local host=$1 cmd="$2" cmd_args="$3" rc
    local marscmd="marsadm --timeout=$marsadm_timeout $cmd $cmd_args"
    lib_vmsg "  executing $marscmd on $host"
    lib_remote_idfile $host $marscmd
    rc=$?
    marsview_get $host lv-1-2 >/dev/null
    if [ $rc -ne 0 ]; then
        return $rc
    fi
    # replace - with _ and remove everything after last blank 
    local post_condition_check=${cmd//-/_}
    post_condition_check=${post_condition_check%% *}
    post_condition_check=marsadm_check_post_condition_${post_condition_check}
    case "$cmd" in # ((
        resize*|pause-sync*|primary*|secondary*) \
             $post_condition_check $host "$cmd_args"
             ;;
        _*) lib_exit 1 "invalid command starting with - or _"
             ;;
        *) :
        ;;
    esac
}

function marsadm_get_role
{
    local host=$1 res=$2 output
    output=$(lib_remote_idfile $host "marsadm role $res") || lib_exit 1
    expr "$output" : '.*I am actually \([^ ][^ ]*\).*'
}

function marsadm_check_post_condition_primary
{
    marsadm_check_post_condition_role_switch "primary" "$@"
}

function marsadm_check_post_condition_secondary
{
    marsadm_check_post_condition_role_switch "secondary" "$@"
}

function marsadm_get_highest_to_delete_nr
{
    local host=$1
    local ret rc
    local ls_out_old="x" ls_out_act maxcount=10 count=0
    # wait until ls output is stable
    while true; do
        ls_out_act="$(lib_remote_idfile $host 'ls -1 $global_mars_directory/todo-global/delete-[0-9]*[0-9]')"
        rc=$?
        if [ -z "$ls_out_act" -o $rc -ne 0 ]; then
            echo 0
            return
        fi
        if [ "$ls_out_act" -eq "$ls_out_old" ]; then
            break
        fi
        let count+=1
        sleep 1
        lib_vmsg "  $count retries: ls_out_old="$'\n'"$ls_out_old"$'\n'"ls_out_act="$'\n'"$ls_out_act"
        if [ $count -eq $maxcount ]; then
            lib_exit 1 "max number of loops exceeded"
        fi
        ls_out_old="$ls_out_act"
        continue
    done
    ret=$(echo "$ls_out_act" | sed 's/.*-//' | sort -n | tail -1)
    if ! expr "$ret" : '^[0-9][0-9]*$' >/dev/null; then
        lib_exit 1 "cannot determine number of $global_mars_directory/todo-global/delete-* files on $host (ret=$ret)"
    fi
    echo $ret
}

function marsadm_get_deleted_link_value
{
    local host=$1
    local ret
    local link=$global_mars_directory/todo-global/deleted-$host
    ret=$(lib_remote_idfile $host "readlink $link")
    if [ -z "$ret" ]; then
        ret=0
    fi
    if ! expr "$ret" : '^[0-9][0-9]*$' >/dev/null; then
        lib_exit 1 "link value $ret of $host:$link is not a number"
    fi
    echo $ret
}

function marsadm_get_number_of_hidden_delete_symlinks
{
    local host=$1 res=$2
    local resdir ret
    resdir="${resource_dir_list[$res]}"
    ret=$(lib_remote_idfile $host "ls -1 $resdir/.delete-* | wc -l") || \
                                                                    lib_exit 1
    if ! expr "$ret" : '^[0-9][0-9]*$' >/dev/null; then
        lib_exit 1 "cannot determine number of $resdir/.delete-* files on $host"
    fi
    echo $ret
}

function marsadm_check_post_condition_role_switch
{
    local role_req=$1 host=$2 cmd_args=("$3")
    local res=${cmd_args[0]}
    local role_act ls_returncode_req ls_returncode_act maxcount=5 count=0
    case $role_req in # (((
        primary) marsadm_do_cmd $host "wait-resource" "$res is-device-on" || lib_exit 1
                 ls_returncode_req=0
              ;;
        secondary) marsadm_do_cmd $host "wait-resource" "$res is-device-off" || lib_exit 1
                 ls_returncode_req=2
              ;;
              *) lib_exit 1 "invalid role $role_act"
              ;;
    esac
    while true; do
        role_act=$(marsadm_get_role $host $res) || lib_exit 1
        if [ "$role_act" = "$role_req" ]; then
            break;
        fi
        let count+=1
        sleep 1
        lib_vmsg "  waited $count for role expected = $role_req (actual role = $role_act)"
        if [ $count -eq $maxcount ]; then
            lib_exit 1 "maxwait $maxcount exceeded"
        fi
    done
    count=0
    while true; do
        lib_vmsg "  role = $role_act, trying ls $(resource_get_data_device $res) on $host"
        lib_remote_idfile $host "ls -l --full-time $(resource_get_data_device $res)"
        ls_returncode_act=$?
        if [ $ls_returncode_req -eq $ls_returncode_act ]; then
            break;
        fi
        let count+=1
        sleep 1
        lib_vmsg "  waited $count for ls returncode expected = $ls_returncode_req (actual rc = $ls_returncode_act)"
        if [ $count -eq $maxcount ]; then
            lib_exit 1 "maxwait $maxcount exceeded"
        fi
    done
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
    echo "${resource_dir_list[$res]}/log-"
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
    marsview_wait_for_state $host $res "repl" "$repl_state" \
                            $marsview_wait_for_state_time || lib_exit 1
}

function marsadm_set_proc_sys_mars_parameter
{
    local host=$1 param="$2" param_value="$3"
    local dir=/proc/sys/mars
    lib_vmsg "  setting $dir/$param to $param_value on $host"
    lib_remote_idfile $host "echo $param_value >$dir/$param" || lib_exit 1
}

function marsadm_check_warnings_and_disk_state
{
    local host=$1 res=$2 situation="$3"
    # wait a little for the files required
    sleep 2
    case $situation in # ((
        apply_stopped_after_disconnect)
            local link_value not_applied restlen_in_warn_file
            local warn_file="$lib_err_total_log_file"
            local link=$(lib_linktree_get_res_host_linkname $host $res "replay")
            link_value=$(lib_remote_idfile $host "readlink $link") || lib_exit 1

            # extract last int from log-000000001-istore-test-bs7,317023740,2564
            not_applied=${link_value##*,}
            if ! expr "$not_applied" : '^[0-9][0-9]*$' >/dev/null; then
                lib_exit 1 "cannot determine last int in $link_value"
            fi
            lib_vmsg "  number of bytes not applied: $not_applied"
            if [ $not_applied -eq 0 ];then
                marsview_wait_for_state $host $res "disk" "Outdated\[F\]" \
                                    $marsview_wait_for_state_time || lib_exit 1
                return 0
            fi
            lib_vmsg "  checking file $warn_file on $host"
            restlen_in_warn_file=$(marsadm_get_number_bytes_unreadable_logend \
                                   $host $res $warn_file) || lib_exit 1
            if [ $restlen_in_warn_file -ne $not_applied ]; then
                lib_exit 1 "not applied = $not_applied != $restlen_in_warn_file = restlen in $warn_file"
            fi
            marsview_wait_for_state $host $res "disk" "Outdated\[FA\]" \
                                    $marsview_wait_for_state_time || lib_exit 1
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
              "egrep '(mars|xio)_logger.*restlen =.*truncated' $warn_file | tail -1")\
                                                            || lib_exit 1
    # grep_out = ... but available data restlen = 2564. Was the ...
    restlen=${grep_out##*available data restlen = }
    restlen=${restlen%%.*}
    if ! expr "$restlen" : '^[0-9][0-9]*$' >/dev/null; then
        echo "  cannot determine restlen in $grep_out" >&2
        echo "  file $warn_file:" >&2
        lib_remote_idfile $host "cat $warn_file | sed 's/^/    /'" >&2
        lib_exit 1 "cannot determine restlen in $grep_out"
    fi
    echo $restlen
}

function marsadm_host_is_primary
{
    local host=$1 res=$2
    local link link_status
    local link="$(lib_linktree_get_primary_linkname $host $res)"
    lib_linktree_check_link $host "$link" 1
    link_status=$?
    if [ $link_status -ne ${global_link_status["link_ok"]} ]; then
        return 0
    fi
    return 1
}

function marsadm_host_is_designated_primary
{
    local host=$1 res=$2
    local link link_status
    local link="$(lib_linktree_get_designated_primary_linkname $res)"
    lib_linktree_check_link $host "$link" $host
    link_status=$?
    if [ $link_status -ne ${global_link_status["link_ok"]} ]; then
        return 0
    fi
    return 1
}

function marsadm_primary_force
{
    local host=$1 res=$2
    marsadm_do_cmd $host "disconnect" "$res" || lib_exit 1
    marsadm_do_cmd $host "primary --force" "$res" || lib_exit 1
    marsadm_do_cmd $host "connect" "$res" || lib_exit 1
}
