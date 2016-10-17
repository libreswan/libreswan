#!/bin/sh -e

awk '
BEGIN {
    debug = 0
}

/<manvolnum>/ && !manvolnum {
    manvolnum = gensub(/[^0-9]*/, "", "g")
    if (debug) print "manvolnum:", manvolnum >> "/dev/stderr"
}
/<refname>/ {
    refname = $0
    if (debug) print "refname:", refname >> "/dev/stderr"
    refname = gensub(/[^>]*>/, "", "1", refname)
    if (debug) print "refname:", refname >> "/dev/stderr"
    refname = gensub(/<.*/, "", "1", refname)
    if (debug) print "refname:", refname >> "/dev/stderr"
    refname = gensub(/ /, "_", "g", refname)
    if (debug) print "refname:", refname >> "/dev/stderr"
    print refname "." manvolnum
}
' $@
