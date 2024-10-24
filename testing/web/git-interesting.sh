#!/bin/sh


if test $# -ne 2; then
    cat >> /dev/stderr <<EOF

Usage:

    $0 <repodir> <gitrev>

Where <repodir> defaults to the current directory.  XXX: The parameter
order needs to be reversed.

Examine <gitrev> in <repodir> and determine if it is sufficiently
"interesting" to be worth testing.

The output is one of:

    tag: <tagname>
    	a commit containing a tag
    merge: <parents>
        a merge point
    branch: <children>
        a branch point
    true
        a commit that changes build and/or source files
    false
        the commit is not interesting

EOF
    exit 1
fi


set -eu

bindir=$(realpath $(dirname $0))
rutdir=$1 ; shift
gitrev=$1 ; shift

# All tags are interesting.
#
# If there is no tag then this command fails with an error so suppress
# that.

tag=$(git -C ${rutdir} describe --exact-match ${gitrev} 2>/dev/null || :)
if test -n "${tag}" ; then
    echo tag: ${tag}
    exit 0
fi

# All merges (commits with more than one parent) are "interesting".

parents=$(git -C ${rutdir} show --no-patch --format=%P ${gitrev})
if test $(echo ${parents} | wc -w) -gt 1 ; then
    echo merge: ${parents}
    exit 0
fi

# All branches (commits with more than one child) are "interesting".
#
# Determining children is messy for some reason: generate a <<parent
# child ...> list of all revisions more recent than GITREV
# (REV.. seems to be interpreted as that) and use that to find
# immediate parents (a child matches $GITREV).

children=$(git -C ${rutdir} rev-list --parents ${gitrev}.. | awk "/ ${gitrev}/ { print \$1}")
if test $(echo ${children} | wc -w) -gt 1 ; then
    echo branch: ${children}
    exit 0
fi

# grep . exits non-zero when there is no input (i.e., the diff is
# empty); and this will cause the command to fail.

if git -C ${rutdir} show "${gitrev}^{commit}" \
       Makefile \
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

echo "false"
exit 1
