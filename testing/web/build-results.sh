#!/bin/sh

if test "$#" -lt 2; then
    cat >> /dev/stderr <<EOF

Usage:

   $0 <repodir> <resultsdir> <destdir>

Use "kvmrunner.py> to create a results web page under <destdir>.

If <previousdir> is specified, use that as a baseline when generating
the results.  If <previousdir> is not specified, apply a heuristic to
determine the previous <destdir>.

EOF
    exit 1
fi

set -euxv

cwd=$(pwd)
webdir=$(cd $(dirname $0) && pwd)
repodir=$(cd $1 && pwd) ; shift
resultsdir=$(cd $1 && pwd) ; shift
destdir=$(cd $1 && pwd) ; shift

test -d ${repodir}/testing/pluto

(
    # kvmresults needs to be in the current directory
    cd ${resultsdir}
    ${webdir}/json-results.sh \
	     --json ${repodir}/results.json \
	     --testing-directory ${repodir}/testing \
	     .
)

rsync ${repodir}/results.json ${destdir}
rsync ${webdir}/lsw*.{css,js} ${destdir}
rsync ${webdir}/results*.{html,css,js} ${destdir}
rsync ${webdir}/results.html ${destdir}/index.html
