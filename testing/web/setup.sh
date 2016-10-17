#!/bin/sh

set -eu

# check dependencies installed
rpm -q jq

webdir=$(dirname $0)
resultsdir=${HOME}/results

cp ${webdir}/*.{js,css,html} ${resultsdir}
ln -f -s status.html ${resultsdir}/index.html

mkdir -p ${resultsdir}/js
cd ${resultsdir}/js

for tgz in https://github.com/nuxy/Tidy-Table/archive/3.0.1.tar.gz ; do
    if test ! -r $(basename ${tgz}) ; then
	wget ${tgz}
	tar xf $(basename ${tgz})
    fi
done

for js in \
    https://d3js.org/d3.v4.min.js
do
    if test ! -r $(basename ${js}) ; then
	wget ${js}
    fi
done
