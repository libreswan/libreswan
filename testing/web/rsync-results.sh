#!/bin/sh

set -eu

if test $# -lt 2; then
    cat >> /dev/stderr <<EOF

Usage:

  $0 <repodir> <destdir>

Rsync test results under <repodir>/testing/pluto to <destdir>.

EOF
    exit 1
fi

repodir=$1 ; shift
destdir=$1 ; shift

test -d ${repodir}/testing/pluto

# relative: so that the transfer preserves the existing structure
# (otherwise it would flatten it).
#
# -printf %P\n prints the relative path (below testing/pluto).

find ${repodir}/testing/pluto \
     -maxdepth 3 \
     \( \
     -path '*/pluto/*/OUTPUT/*.txt' -o \
     -path '*/pluto/*/OUTPUT/*.diff' -o \
     -path '*/pluto/*/OUTPUT/*.log' -o \
     -path '*/pluto/*/OUTPUT/RESULT' \
     \) \
     -printf '%P\n' \
    | rsync --relative --itemize-changes \
	    --files-from=- \
	    ${repodir}/testing/pluto \
	    ${destdir}
