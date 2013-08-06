#!/usr/bin/env bash
# Copyright 2013 Frank Liepold /  1&1 Internet AG
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

function make_mars_prepare
{
    if [ -n "$make_mars_save_boot_configuration" ];then
        eval $make_mars_save_boot_configuration "make_mars_restore_id"
        echo "  saved current boot configuration (id=$make_mars_restore_id)"
    fi
}

function make_mars_finish
{
    if [ -n "$make_mars_restore_boot_configuration" ];then
        if [ -z "$make_mars_restore_id" ];then
            lib_exit 1 "boot configuration has not been saved"
        fi
        eval $make_mars_restore_boot_configuration $make_mars_restore_id
        echo "  $BASH_SOURCE:$LINENO: restored current boot configuration (id=$make_mars_restore_id)"
    fi
}

function make_mars_run
{
    local src_dirs dir

    declare -A src_dirs

    src_dirs["mars"]=$make_mars_src_directory
    src_dirs["kernel"]=$make_mars_kernel_src_directory
 
    for dir in ${src_dirs[@]};do
        if [ ! -d "$dir" ];then
            lib_exit 1 "src directory $dir not found"
        fi
    done

    make_mars_check_and_build_link ${src_dirs["mars"]} ${src_dirs["kernel"]} \
                                   $make_mars_build_link

    make_mars_check_kconfig_file ${src_dirs["kernel"]}/$make_mars_kconfig_file

    make_mars_check_block_makefile ${src_dirs["kernel"]}/$make_mars_block_makefile

    lib_vmsg "  call to make in ${src_dirs["kernel"]}"
    cd ${src_dirs["kernel"]} || lib_exit 1
    make oldconfig || lib_exit 1
    make || lib_exit 1
    main_error_recovery_functions["grub_restore_boot_configuration"]=1
    sudo make install modules_install || lib_exit 1

    make_mars_check_install

    local kernel_release
    kernel_release=$(make_mars_get_kernel_release) || lib_exit 1
    sudo depmod "$kernel_release" || lib_exit 1
}

function make_mars_get_kernel_release
{
    local file_name=$make_mars_kernel_src_directory/$make_mars_kernel_release_file
    if [ ! -f $file_name ];then
        echo  "  file $file_name not found" >&2
        exit 1
    fi
    cat $file_name
}

function make_mars_check_install
{
    local kernel_release
    kernel_release=$(make_mars_get_kernel_release) || lib_exit 1
    modinfo -k "$kernel_release" mars || lib_exit 1
}

function make_mars_check_block_makefile
{
    local block_makefile=$1
    lib_vmsg "  updating $block_makefile with CONFIG_MARS"
    if ! grep -w CONFIG_MARS $block_makefile; then
        echo 'obj-$(CONFIG_MARS)              += mars/kernel/' >>$block_makefile
    fi
}

function make_mars_check_kconfig_file
{
    local kconfig_file=$1
    if grep "$make_mars_kconfig_replace_text" $kconfig_file >/dev/null; then
        return 0
    fi
    lib_vmsg "  inserting $make_mars_kconfig_replace_text in $kconfig_file"
    awk '/^ *if  *BLOCK *$/ { in_block = 1 }
         in_block == 1 && /^ *endif/ {
             print "    '"$make_mars_kconfig_replace_text"'\n\n"
             in_block = 0
         }
         { print $0 }
        ' < $kconfig_file > $kconfig_file.new || lib_exit 1
    mv $kconfig_file{.new,}
}

function make_mars_check_and_build_link
{
    local mars_dir=$1 kernel_dir=$2 
    local link=$kernel_dir/$3
    local link_target
    if [ ! -L $link ];then
        echo "  missing link $link will be created"
        ln -s $mars_dir $link || lib_exit 1
    fi
    link_target=$(readlink $link)
    if [ -z "$link_target" ];then
        lib_exit 1 "cannot read link $link"
    fi
    if [ "$link_target" != "$mars_dir" ];then
        lib_exit 1 "link $link points to $link_target instead of $mars_dir"
    fi
}



