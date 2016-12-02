#!/bin/sh

if test "$#" -ne 2; then
    cat >> /dev/stderr <<EOF

Usage:

   $0 <repodir> <summarydir>

Create a summary-of-results web page in <summarydir> from
<summarydir>/*/ using <repodir> as a reference.

This script does mot modify <repodir>.

EOF
    exit 1
fi

set -euxv

webdir=$(dirname $0)

repodir=$1 ; shift
summarydir=$1 ; shift

# Construct the summary from all the results; order somewhat
# assending.

${webdir}/json-summary.sh \
	 --json ${summarydir}/summaries.json \
	 $(ls ${summarydir}/*/results.json | sort -V)

# install

cp ${webdir}/lsw*.{css,js} ${summarydir}
cp ${webdir}/summary*.{html,css,js} ${summarydir}
ln -f -s summary.html ${summarydir}/index.html
