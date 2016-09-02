#!/bin/sh

if test "$#" -lt 2; then
    cat <<EOF > /dev/stderr

Usage:

   $0 <repodir> <destdir> [ <previousdir> ]

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
if test $# -gt 0; then
    baseline=$(cd $1 && pwd) ; shift
else
    # Use "rank" to determine the previous to this directory name,
    # need to convert it to an absolute path.
    baseline=$(${webdir}/gime-git-elder.sh ${repodir} ${destdir})
fi

(
    cd ${destdir}
    ${webdir}/results.sh \
	     $(test -n "${baseline}" && echo --baseline "${baseline}") \
	     --testing-directory ${repodir}/testing \
	     .
) > ${destdir}/results.tmp
jq -s '.' ${destdir}/results.tmp > ${destdir}/results.new
rm ${destdir}/results.tmp

cp ${webdir}/*.{html,css,js} ${destdir}
ln -f -s results.html ${destdir}/index.html

mv ${destdir}/results.new ${destdir}/results.json
