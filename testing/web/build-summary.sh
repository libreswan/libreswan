#!/bin/sh

if test "$#" -lt 3; then
    cat <<EOF > /dev/stderr

Usage:

   $0 <repodir> <summarydir> <results.json> ...

Create the results summary page in <summarydir> from
<results.json>... and using <repodir> (read-only) for branch
information.

EOF
    exit 1
fi

set -euxv

repodir=$(cd $1 && pwd) ; shift
summarydir=$(cd $1 && pwd) ; shift
webdir=$(cd $(dirname $0) && pwd)

# generate the individual summary entries
${webdir}/summary.sh ${repodir} ${summarydir} "$@" > ${summarydir}/summary.tmp

# mash them together as a proper JSON list
jq -s '.'  ${summarydir}/summary.tmp >  ${summarydir}/summary.new
rm  ${summarydir}/summary.tmp

# install
cp ${webdir}/lsw*.{css,js} ${summarydir}
cp ${webdir}/summary*.{html,css,js} ${summarydir}
ln -f -s summary.html ${summarydir}/index.html
mv  ${summarydir}/summary.new  ${summarydir}/summary.json
