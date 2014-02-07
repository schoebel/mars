
prepare_list=""
setup_list=""
run_list=""
cleanup_list=""
finish_list=""

function main
{
    ok=1
    main_start_time=$(date +'%Y%m%d%H%M%S')
    for script in $prepare_list; do
	if (( ok )); then
	    (( main_verbose_script )) && echo "calling $script"
	    $script || ok=0
	fi
    done
    for script in $setup_list; do
	if (( ok )); then
	    (( main_verbose_script )) && echo "calling $script"
	    $script || ok=0
	fi
    done
    for script in $run_list; do
	if (( ok )); then
	    (( main_verbose_script )) && echo "calling $script"
	    $script || ok=0
	fi
    done
    for script in $cleanup_list; do
	(( main_verbose_script )) && echo "calling $script"
	$script
    done
    for script in $finish_list; do
	(( main_verbose_script )) && echo "calling $script"
	$script
    done
    return $(( !ok ))
}

function main_test_no_longer_in_use
{
    echo "This test is kept only for historical reasons and does not run anymore"
}
