#!/bin/sh

if test $# -ne 2; then
    cat <<EOF > /dev/stderr
Usage: $0 <repo> <gitrev>
Print the date for the given rev as YYYY-MM-DD HH:MM
EOF
    exit 1
fi

repo=$(cd $1 && pwd) ; shift
rev=$1 ; shift
seconds=$(cd ${repo} ; git log -n1 --format="%ct" ${rev})
date -u -d @${seconds} '+%Y-%m-%d %H:%M'
