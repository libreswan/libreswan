#!/bin/sh

usage() {
    cat >> /dev/stderr <<EOF

Usage:

    $0 [ <repodir> ] <gitrev>

Where <repodir> defaults to the current directory.  XXX: The parameter
order needs to be reversed.

Examine <gitrev> in <repodir> and determine if it is sufficiently
"interesting" to be worth testing.

"interesting" is any of:

    - a commit with a tag

    - a merge point

    - a branch point

    - a commit that changes build and/or source files

EOF
}

set -eu

webdir=$(dirname $0)

# XXX: arguments are backwards

case $# in
    0 ) usage ; exit 1 ;;
    1 ) gitrev=$1   ; repodir=. ;;
    2 ) gitrev=$2   ; repodir=$1 ;;
    * ) echo "Too many arguments." ; usage ; exit 1 ;;
esac

# All tags are interesting.
#
# If there is no tag then this command fails with an error so suppress
# that.

tag=$(cd ${repodir} && git describe --exact-match ${gitrev} 2>/dev/null || :)
if test -n "${tag}" ; then
    echo tag: ${tag}
    exit 0
fi

# All merges (commits with more than one parent) are "interesting".

parents=$(cd ${repodir} && git show --no-patch --format=%P "${gitrev}^{commit}")
if test $(echo ${parents} | wc -w) -gt 1 ; then
    echo merge: ${parents}
    exit 0
fi

# All branches (commits with more than one child) are "interesting".
#
# Determining children is messy for some reason.  Search revisions
# more recent than GITREV (REV.. seems to be interpreted as that) for
# a parent matching GITREV.

children=$(cd ${repodir} && git rev-list --parents ${gitrev}.. | \
    while read commit parents ; do
	case " ${parents} " in
	    *" ${gitrev}"* ) echo ${commit} ;;
	esac
    done)
if test $(echo ${children} | wc -w) -gt 1 ; then
    echo branch: ${children}
    exit 0
fi

cd ${repodir}

# grep . exits non-zero when there is no input (i.e., the diff is
# empty); and this will cause the command to fail.

if git show "${gitrev}^{commit}" \
       Makefile \
       Makefile.inc \
       lib \
       mk \
       programs \
       include \
       testing/pluto \
       testing/sanitizers \
       testing/baseconfigs \
	| grep . > /dev/null ; then
    echo "true"
    exit 0
fi

exit 1
