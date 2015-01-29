#!/bin/bash

function get_option_help
{
    local verbose=$1
    ./marsadm --verbose=$verbose --help |\
	awk '/^<command>/ { x=0; }; { if(x) print $0; }; /^<global_option>/ { x=1; };' |\
	sed 's/\(--[-a-z_]\+\)/\\fB\1\\fR/'

}

function get_cmd_help
{
    local verbose=$1
    ./marsadm --verbose=$verbose --help |\
	awk '/^<resource_name>/ { x=0; }; { if(x) print $0; }; /^<command>/ { x=1; };' |\
	sed 's/\(^ *[-a-z_]\+$\)/\\fB\1\\fR/'
}

(
    cat <<EOF
.TH marsadm 8 "$(date "+%B %d, %Y")" "MARS $(git describe --tags)" "MARS Admin Tool"
.SH NAME
marsadm - Administration tool for MARS.\" marsadm

.SH SYNOPSIS
.B marsadm -h --help
.br
.B marsadm -v --version
.br
.B marsadm {<global_option>} <command> [<resource_name> | all | {arg}]
.br
.B marsadm {<global_option>} view[-<macroname>] [<resource_name> | all]
.br

.SH DESCRIPTION
MARS is a kernel-level asynchronous replication system for block devices.
It is tailored for long-distance replication and through network
bottlenecks.
By default, it works asynchronously (in contrast to DRBD).
.br
More infomation on concepts and differences to DRDB can be found at
https://github.com/schoebel/mars/blob/master/docu/MARS_LinuxTag2014.pdf?raw=true

.SH OPTIONS
EOF

get_option_help 0

cat <<EOF

.SH ORDINARY COMMANDS
EOF

get_cmd_help 0

cat <<EOF

.SH EXPERT COMMANDS
EOF

get_cmd_help -1

cat <<EOF

.SH 1&1 INTERNAL COMMANDS
EOF

get_cmd_help -2

cat <<EOF

.SH DEPRECATED COMMANDS
EOF

get_cmd_help -3

cat <<EOF

.SH SELECTED MACROS
This is a small selection of some useful macros for humans. For a full list and for detailed information as well as for scripting instructions, please refer to the PDF manual.

\fB  view all\fR
    Show standard information about the local state of MARS at the local host.

\fB  view-replstate all\fR
    Show only the replication state part of plain view.

\fB  view-flags all\fR
    Show only the flags part from plain view.

\fB  view-primarynode all\fR
    Display (none) or the hostname of the current designated primary.

\fB  view-the-pretty-err-msg all\fR
    Show reported error messages.

\fB  view-the-pretty-wrn-msg all\fR
    Show reported warnings.

\fB  view-is-emergency all\fR
    Tell whether emergency mode has been entered.

\fB  view-rest-space\fR
    Show the internal rest space calculations used for calculating emergency mode. This value should not go down to 0.

\fB  view-get-disk all\fR
    Show the underlying disk name for each resource.

.SH AUTHOR
Written by Thomas Schoebel-Theuer.

.SH COPYRIGHT
Copyright 2010-2015 Thomas Schoebel-Theuer

Copyright 2011-2015 1&1 Internet AG

This is free software; see the source for copying conditions.
There is NO warranty; not even for MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE.

.SH NOTES
http://schoebel.github.io/mars/

http://github.com/schoebel/mars/
EOF
) |\
    sed 's/</\\fI/g' |\
    sed 's/>/\\fR/g' |\
    sed 's/-/\\-/g' |\
    tee marsadm.8
