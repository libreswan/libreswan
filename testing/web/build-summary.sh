#!/bin/sh

if test "$#" -lt 3; then
    cat <<EOF > /dev/stderr

Usage:

   $0 <repodir> <basedir> <results.json> ...

Using <repodir> as a reference for branch information, create/update
the summary web page in <basedir> using <basedir>/*/results.json as
input.

EOF
    exit 1
fi

set -euxv

repodir=$(cd $1 && pwd) ; shift
basedir=$(cd $1 && pwd) ; shift
webdir=$(cd $(dirname $0) && pwd)

${webdir}/summary.sh ${repodir} ${basedir} "$@" > ${basedir}/summary.tmp
jq -s '.'  ${basedir}/summary.tmp >  ${basedir}/summary.new
rm  ${basedir}/summary.tmp

cp ${webdir}/*.{html,css,js} ${basedir}
ln -f -s summary.html ${basedir}/index.html

mv  ${basedir}/summary.new  ${basedir}/summary.json
