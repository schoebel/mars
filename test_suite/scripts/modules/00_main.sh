
prepare_list=""
setup_list=""
run_list=""
cleanup_list=""
finish_list=""

function main
{
    ok=1
    for script in $prepare_list; do
	if (( ok )); then
	    (( verbose_script )) && echo "calling $script"
	    $script || ok=0
	fi
    done
    for script in $setup_list; do
	if (( ok )); then
	    (( verbose_script )) && echo "calling $script"
	    $script || ok=0
	fi
    done
    for script in $run_list; do
	if (( ok )); then
	    (( verbose_script )) && echo "calling $script"
	    $script || ok=0
	fi
    done
    for script in $cleanup_list; do
	(( verbose_script )) && echo "calling $script"
	$script
    done
    for script in $finish_list; do
	(( verbose_script )) && echo "calling $script"
	$script
    done
    return $(( !ok ))
}
