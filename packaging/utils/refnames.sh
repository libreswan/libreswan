#!/bin/sh -e

awk '
BEGIN {
    debug = 0
}

/<manvolnum>[0-9]+<\/manvolnum>$/ && !manvolnum {
    manvolnum = $0
    gsub(/[^0-9]*/, "", manvolnum)
    print "manvolnum:", manvolnum >> "/dev/stderr"
}

/<refname>/ {
    refname = $0
    if (debug) print "refname:", refname >> "/dev/stderr"
    sub(/[^>]*>/, "", refname)
    if (debug) print "refname:", refname >> "/dev/stderr"
    sub(/<.*/, "", refname)
    if (debug) print "refname:", refname >> "/dev/stderr"
    gsub(/ /, "_", refname)
    if (debug) print "refname:", refname >> "/dev/stderr"
    print refname "." manvolnum
}
' $@
