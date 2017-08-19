#!/bin/bash

if [[ $EUID -ne 0 ]]; then
	echo "This script requires root permission" 1>&2
	exit 1
fi

if [ "$#" -lt 1 ]; then
	echo "Usage : $0 <enable/disable>"
	exit 0
fi

option="$1"

if [[ "$option" == "enable" ]]; then
	echo 2 > /proc/sys/kernel/randomize_va_space
elif [[ "$option" == "disable" ]]; then
	echo 0 > /proc/sys/kernel/randomize_va_space
else
	echo "Invalid option."
fi
