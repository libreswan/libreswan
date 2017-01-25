#!/bin/sh

# Reverse engineer 2016-08-08-0556-3.18-51-g00a7f80-dirty-master

for d in "$@" ; do
    # reallink?
    realpath ${d} | sed -n -e 's/.*-g\([^-]*\)-[^/]*$/\1/p'
done
