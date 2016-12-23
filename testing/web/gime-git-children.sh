#!/bin/sh

if test $# -lt 2 ; then
    cat >> /dev/stderr <<EOF

Usage:

    $0 <repodir> <gitrev> [ <origin> ]

List the children of <gitrev>, one per line, first-child first.

EOF
    exit 1
fi

webdir=$(dirname $0)

repodir=$1 ; shift
gitrev=$1 ; shift
if test $# -gt 0; then
    origin=$1 ; shift
else
    origin=$(${webdir}/gime-git-origin.sh ${repodir})
fi

cd ${repodir}

# Asking rev-list about children at ${gitrev} does nothing useful so
# start earlier.
git rev-list --parents ${gitrev}..${branch} | \
    while read commit parents ; do
	case " ${parents} " in
	    *" ${gitrev} "* )
		git show --no-patch --format=%h ${commit} ;;
	esac
    done
