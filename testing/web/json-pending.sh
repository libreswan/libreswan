#!/bin/sh

if test $# -lt 2 ; then
    cat >>/dev/stderr <<EOF

Usage:

    $0 [ --json json ] <repodir> <branch>

List pending changes (i.e., those in origin but not in <branch>) as
a <json> table.

By default per-change JSON objects are written to standard out.
Specify --json <json> to store a json list into a file.

EOF
    exit 1
fi


json=
repodir=
branch=
while test $# -gt 0 ; do
    case $1 in
	--json ) shift ; json=$1 ; shift ;;
	-* )
	    echo "Unknown option: $*" 1>&2
	    exit 1
	    ;;
	* )
	    if test -z "${repodir}" ; then
		repodir=$1 ; shift
	    elif test -z "${branch}" ; then
		branch=$1 ; shift
	    else
		echo "Unexpected parameter: $*" 1>&2
		exit 1
	    fi
	    ;;
    esac
done

if test -z "${repodir}" -o -z "${branch}" ; then
    echo "Missing options" 1>&2
    exit 1
fi

webdir=$(dirname $0)
origin=$(${webdir}/gime-git-origin.sh ${repodir} ${branch})

${webdir}/gime-git-revisions.sh ${repodir} ${branch}..${origin} | \
    while read rev ; do \
	if ${webdir}/git-interesting.sh ${repodir} ${rev} ; then
	    (
		cd ${repodir}
		git show --format='%h%n%cI%n%s' ${rev} \
		    | jq --raw-input '.' \
		    | jq -s '{ hash: .[0], commit_date: .[1], subject: .[2] }'
	    )
	fi
    done | \
	if test -n "${json}" ; then
	    jq -s '.' > ${json}.tmp
	    mv ${json}.tmp ${json}
	else
	    cat
	fi
