#!/bin/sh

if test $# -ne 2; then
    cat >> /dev/stderr <<EOF

Usage:

   $0 <repodir> <gitrev>

Print the date for the given rev in ISO format down to seconds vis:
YYYY-MM-DDTHH:MM:SS+<offset>

EOF
    exit 1
fi

repo=$(cd $1 && pwd) ; shift
rev=$1 ; shift
seconds=$(cd ${repo} ; git log -n1 --format="%ct" ${rev})
date -u -d @${seconds} -Iseconds
