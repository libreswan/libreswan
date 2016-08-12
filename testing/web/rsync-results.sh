#!/bin/sh

set -eu

if test $# -lt 2; then
    cat <<EOF > /dev/stderr

Usage:

  $0 <repodir> <destdir>

Rsync test results under <repodir>/testing/pluto to <destdir>.

EOF
    exit 1
fi

repodir=$(cd $1 && pwd) ; shift
destdir=$(cd $1 && pwd) ; shift

# checksum: slower but avoids double copies when flipping between git
# branches.
#
# relative: so that the transfer preserves the existing structure
# (otherwise it would flatten it).
#
# -printf %P\n prints the relative path (below testing/pluto).

test -d ${repodir}/testing/pluto

find ${repodir}/testing/pluto \
     -maxdepth 3 \
     \( \
     -path '*/pluto/*/OUTPUT/.txt' -o \
     -path '*/pluto/*/OUTPUT/*.diff' -o \
     -path '*/pluto/*/OUTPUT/*.txt' -o \
     -path '*/pluto/*/OUTPUT/RESULT' \
     \) \
     -printf '%P\n' \
    | rsync --checksum --relative --itemize-changes \
	    --files-from=- \
	    ${repodir}/testing/pluto \
	    ${destdir}
