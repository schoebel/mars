#!/bin/bash

old=backup.$$
files="*.h *.c"
#files="mars_buf.h mars_buf.c"

mkdir -p $old || exit $?
cp -a $files $old || exit $?

for i in $files; do
    sed "$1" < $i > $i.tmp || exit $?
    cmp $i $i.tmp || mv $i.tmp $i
    rm -f $i.tmp
done
