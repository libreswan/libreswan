#!/bin/sh

if test "$#" -lt 2; then
    cat >> /dev/stderr <<EOF

Usage:

   $0 <repodir> <destdir>

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
destdir=$(cd $1 && pwd) ; shift

(
    # kvmresults needs to be in the current directory
    cd ${destdir}
    ${webdir}/json-results.sh \
	     --json results.json \
	     --testing-directory ${repodir}/testing \
	     .
)

${webdir}/json-commit.sh ${repodir} HEAD > ${destdir}/commit.json
${webdir}/json-summary.sh ${destdir}/results.json > ${destdir}/summary.json

cp ${webdir}/lsw*.{css,js} ${destdir}
cp ${webdir}/results*.{html,css,js} ${destdir}
ln -f -s results.html ${destdir}/index.html
