#!/bin/sh

EXEC()
{
    echo + "$@" 1>&2
    exec "$@"
}

progname=$(basename $0)
outfile=/tmp/$(hostname).${progname}.callgrind

EXEC valgrind \
     --tool=callgrind \
     --callgrind-out-file=${outfile} \
     --dump-line=yes \
     --separate-threads=yes \
     "$@"
