#!/bin/sh

source ~/tools/shell/lib.sh || exit 1

function usage
{
    echo usage: $(basename $0) config_file >&2
    exit 1
}

function check_config_variables
{
    local config_file=$1 varname

    source $config_file || lib_exit 1

    for varname in "${!config_variables[@]}"; do
        local val
        eval val='$'$varname
        if [ -z "$val" ]; then
            lib_exit 1 "variable $varname not set in $config_file"
        fi
    done
}

function get_conf_var_value
{
    local value=$1 varname=$2
    local ret=${config_variables[$varname]}
    if [ -z "$ret" ]; then
        lib_exit 1 "no entry for variable $varname in config_variables"
    fi
    case $value in # (((
        file) echo $src_dir/${ret##*:};;
        prompt) echo ${ret%%:*};;
        *) lib_exit 1 "invalid value $value for get_conf_var_value";;
    esac
}

function replace_value
{
    local config_varname=$1 value="$2" file prompt
    file=$(get_conf_var_value "file" $config_varname) || lib_exit 1
    prompt=$(get_conf_var_value "prompt" $config_varname) || lib_exit 1
    echo "replacing $prompt in $file"
    if ! grep "^$prompt" $file; then
        lib_exit 1 "cannot find prompt $prompt in $file"
    fi
    sed -i -e "s,^$prompt.*,$prompt=$value," $file || lib_exit 1
    grep "^$prompt" $file || lib_exit 1

}

function replace_config_values
{
    local varname_list="$@" varname val
    for varname in ${varname_list[@]}; do
        eval val='$'$varname
        replace_value "$varname" "$val"
    done
}

function delete_test_entry
{
    local test_entry="$1" file=$2 
    local pattern="^ *\<$test_entry\>"
    echo "deleting test $test_entry from $file"
    if ! grep "$pattern" $file; then
        lib_exit 1 "cannot find pattern $pattern in $file"
    fi
    sed -i -e "\,$pattern,d" $file || lib_exit 1
}

function delete_some_tests
{
    local file=$1 t
    [ -r $file ] || lib_exit 1 "echo file $file does not exist or is not readable"
    for t in $tests_to_skip; do
        delete_test_entry "$t" $file
    done
}

function set_default_configs
{
    tests_to_skip=" "
}

function set_globals_depending_on_configs
{
    cronjob_script=$src_dir/mars_test_cronjob.sh
}

[ $# -ne 1 ] && usage

config_file=$1

[ -r $config_file ] || lib_exit 1 "echo file $config_file does not exist or is not readable"

src_origin=/home/fl/mars/test_suite

# index = name of config variable, value = prompt:file, where file is the default-*.conf where the
# value of the config variable is defined
declare -A config_variables
config_variables=(\
    ["src_dir"]=" : " \
    ["host_list"]="main_host_list:default-main.conf" \
    ["checkout_dir"]="checkout_mars_src_directory:default-checkout_mars.conf" \
    ["branches_to_test"]="checkout_mars_git_branch:default-checkout_mars.conf" \
    ["base_dir"]="main_base_directory:default-main.conf" \
    ["install_mars_src_dir"]="install_mars_src_directory:default-install_mars.conf" \
    ["make_mars_src_dir"]="make_mars_src_directory:default-make_mars.conf" \
    ["mars_kernel_src_dir"]="checkout_mars_kernel_src_directory:default-checkout_mars.conf" \
    ["make_mars_kernel_src_dir"]="make_mars_kernel_src_directory:default-make_mars.conf" \
    ["tests_to_skip"]=" : " \
                )

set_default_configs

check_config_variables $config_file

set_globals_depending_on_configs

if [ "$src_origin" != "$src_dir" ]; then
    echo "fetching origin in $src_dir"
    cd $src_dir || lib_exit 1 "cannot cd $src_dir"
    git fetch origin || lib_exit 1
    git checkout master || lib_exit 1
    git reset --hard origin/master || lib_exit 1

    replace_config_values "host_list" "checkout_dir" "base_dir" "install_mars_src_dir" \
                          "make_mars_src_dir" "mars_kernel_src_dir" \
                          "make_mars_kernel_src_dir"
    delete_some_tests $cronjob_script


    echo "fetching origin in $checkout_dir"
    cd $checkout_dir || lib_exit 1 "cannot cd $checkout_dir"
    git fetch origin || lib_exit 1
fi


for branch in $branches_to_test; do
    replace_value "branches_to_test" "$branch"

    echo TESTING branch $branch

    $src_dir/mars_test_cronjob.sh $src_dir
done
