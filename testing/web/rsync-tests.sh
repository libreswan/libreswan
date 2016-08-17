#!/bin/sh

checkout=true
while test $# -gt 0; do
    case $1 in
	--no-checkout ) checkout=false ; shift ;;
	--checkout ) checkout=true ; shift ;;
	--*) echo Unknown option $1 1>&2 ; exit 1 ;;
	* ) break ;;
    esac
done

if test $# -lt 2; then
    cat <<EOF > /dev/stderr

Usage:

  $0 [ --no-checkout ] <repodir> <destdir>

Rsync the test input files under <repodir>/testing/pluto to <destdir>.

EOF
    exit 1
fi

set -eu

repodir=$(cd $1 && pwd) ; shift
destdir=$(cd $1 && pwd) ; shift

webdir=$(cd $(dirname $0) && pwd)

cd ${repodir}
if ${checkout} ; then
    gitrev=$(${webdir}/gime-git-rev.sh ${destdir})
    git checkout ${gitrev} ; shift
fi

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
