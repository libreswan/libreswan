#!/bin/sh

if test $# -lt 2; then
    cat >> /dev/stderr <<EOF

Usage:

  $0 <repodir> <destdir>

Rsync the test input files under <repodir>/testing/pluto to <destdir>.

EOF
    exit 1
fi

set -eu

repodir=$1 ; shift
destdir=$1 ; shift

test -d ${repodir}/testing/pluto

# Notes:
#
# -printf %P\n: prints the relative path; i.e., without testing/pluto
#
# -maxdepth 2: keeps the find out of the OUTPUT directory.
#
# -checksum: slower but avoids double copies when flipping between git
# branches.
#
# -relative: so that the transfer preserves the existing structure
# (otherwise it would flatten it).

find ${repodir}/testing/pluto \
     -maxdepth 2 \
     \( \
     -path '*/pluto/TESTLIST' -o \
     -path '*/pluto/*/*.txt' -o \
     -path '*/pluto/*/*.sh' \
     \) \
     -printf '%P\n' \
    | rsync --checksum --relative --itemize-changes \
	  --files-from=- \
	  ${repodir}/testing/pluto \
	  ${destdir}
