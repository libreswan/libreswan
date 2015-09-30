#!/bin/sh -e

# Find anything remotely related to makefiles; used to find makefile
# variable references.  Assume this is being run as .../mk/find.sh.

find $(dirname $(dirname $0))/* \
     -name '*~' -prune \
     -o \
     -type f -path '*/packaging/*' -print \
     -o \
     -type f -name 'Makefile*' -print \
     -o \
     -name '*.mk' -print
