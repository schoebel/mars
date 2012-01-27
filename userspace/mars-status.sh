#!/bin/bash

while true
do
	clear
	date
	/root/mars-status.pl $1 $2
	sleep 2
done
