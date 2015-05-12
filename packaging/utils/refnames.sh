#!/bin/sh -e

cat "$@" \
    | sed -n -e 's;.*<refname>\([\.a-z_0-9 ]*\)</refname>.*$;\1;p' \
    | sed -e 's; ;_;g'
