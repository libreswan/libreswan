#!/bin/sh

if ping -q -i 2 -w 1 -n -c 1 "$@" > /dev/null ; then
    echo up
else
    echo down
fi

