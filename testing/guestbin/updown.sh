#!/bin/sh

{
    echo PLUTO_ARGV="$@"
    printenv
} > /tmp/updown.env

exec ipsec _updown "$@"
