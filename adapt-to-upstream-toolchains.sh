#!/bin/bash

# Purpose:
# Linux kernel upstream may change properties of build toolchains over the years.
# MARS is currently downstream and/or out-of-tree.
# Here we adapt ourselves to the kernel upstream.
# This method should also ease the removal of legacy code from MARS,
# as far as possible, when combined with some old kernels.
# Hopefully, this can help in becoming upstream.
#
# We make some reorg git commits.
# In order to ease "git rebase" and siblings, we make separate
# commits for renames vs resurrections.
# Resurrections are needed for compatibility with old kernels
# and their old toolchains, when combined with old MARS versions.
#
# Our own previous intermediate versions are retained by default.
#
# Checking the resulting commits, and appending more commits is up to you.
# When nothing will actually change, you can remove some of the (intermediate) commits.
#
# Adaptations of any pre-patches to newer kernels is also up to you.

echo -n "Enter new version string with numbers (like 5.4) or press Ctrl-C: "
read new_version

shopt -s nullglob

function cmp_version
{
    local a="$1"
    local b="$2"

    if (( ${a%%.*} < ${b%%.*} )); then
	echo "-1"
    elif (( ${a%%.*} > ${b%%.*} )); then
	echo "1"
    elif [[ "$a" =~ \. ]] && [[ "$b" =~ \. ]]; then
	local a_short="$(echo "$a" | sed 's/^[0-9]*\.//')"
	local b_short="$(echo "$b" | sed 's/^[0-9]*\.//')"
	cmp_version "$a_short" "$b_short"
    elif [[ "$a" =~ \. ]]; then
	# only descend the version hierarchy of a
	local a_short="$(echo "$a" | sed 's/^[0-9]*\.//')"
	cmp_version "$a_short" "0"
    elif [[ "$b" =~ \. ]]; then
	# only descend the version hierarchy of b
	local b_short="$(echo "$b" | sed 's/^[0-9]*\.//')"
	cmp_version "0" "$b_short"
    else
	# no descend possible: treat as equal
	echo "0"
    fi
}

function adapt_file
{
    # parameters
    local old_filename="$1"
    local new_version="${2:-$new_version}"

    # derivatives
    local script="$(basename $0)"
    local txt="toolchains"
    local dirname="$(dirname $old_filename)"
    local new_filename="$dirname/$(basename $old_filename | sed 's/\.v[^.]*$//').v$new_version"

    # filter any intermediate versions
    local med_filename="$old_filename"
    local old_version=""
    local this_version=""
    local i
    for i in $old_filename $old_filename.v*; do
	if ! [[ -s "$i" ]]; then
	    continue
	fi

	this_version="$(echo "$i" | grep -o "[0-9.]*$")"
	if [[ "$this_version" = "" ]]; then
	    continue
	fi

	# ignore out-of-bounds versions
	local cond_A=0
	if [[ "$old_version" = "" ]] || (( $(cmp_version "$old_version" "$this_version") <= 0 )); then
	    (( cond_A++ ))
	fi
	local cond_B=0
	if [[ "$new_version" = "" ]] || (( $(cmp_version "$this_version" "$new_version") <= 0 )); then
	    (( cond_B++ ))
	fi
	if (( !cond_A || !cond_B )); then
	    continue
	fi

	# remember any better matching versions
	old_version=$this_version
	med_filename="$i"
    done

    echo "TRANSFER $med_filename -> $new_filename"

    # checks
    if [[ "$new_filename" = "$med_filename" ]]; then
	echo "Sorry, no change in filename."
	exit 1
    fi

    # Step 1: rename the old file to the new one
    echo git mv $med_filename $new_filename
    git mv $med_filename $new_filename || exit $?
    echo "git commit -m \"$txt: git mv $med_filename -> $new_filename\""
    git commit --no-interactive -m "$txt: git mv $med_filename -> $new_filename" || exit $?

    # Step 2: resurrect the old file and content
    echo cp -a $new_filename $med_filename
    cp -a $new_filename $med_filename || exit $?
    echo git add $med_filename
    git add $med_filename || exit $?
    echo "git commit -m \"$txt: resurrect $med_filename\""
    git commit --no-interactive -m "$txt: resurrect $med_filename" || exit $?

    echo "SUCCESS $med_filename -> $new_filename"
}

git reset || exit $?
git checkout . || exit $?

# Current upstream dependencies of files.
# May change in future.

adapt_file kernel/Kconfig
adapt_file kernel/Kbuild
