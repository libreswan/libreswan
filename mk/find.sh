#!/bin/sh -e

# Find anything remotely related to makefiles; used to find makefile
# variable references.

cd $(dirname $(dirname $0))

find * \
     -name '*~' -prune \
     -o \
     -type f -path 'packaging/*' -print \
     -o \
     -type f -name 'Makefile*' -print \
     -o \
     -name '*.mk' -print
