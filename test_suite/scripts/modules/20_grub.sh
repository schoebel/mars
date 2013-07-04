#!/bin/bash


# writes a unique id to grub_restore_id to be used by
# make_mars_restore_boot_configuration

function grub_save_boot_configuration
{
    grub_restore_id=grub_restore_$(date +'%Y%m%d%H%M%S')
    lib_vmsg "  saving $grub_config_file to $grub_config_file.$grub_restore_id"
    sudo cp $grub_config_file{,.$grub_restore_id} || lib_exit 1
}

function grub_restore_boot_configuration
{
    if [ -z "$grub_restore_id" ];then
        lib_exit 1 "no restore id given"
    fi
    lib_vmsg "  restoring grub.cfg"
    sudo cp $grub_config_file{.$grub_restore_id,} || lib_exit 1
    main_error_recovery_functions["grub_restore_boot_configuration"]=
}

function grub_prepare
{
    grub_save_boot_configuration
}

function grub_finish
{
    grub_restore_boot_configuration
}
