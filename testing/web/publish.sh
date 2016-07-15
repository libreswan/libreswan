#!/bin/sh

set -eux

base=results
basedir=${HOME}/${base}

testingdir=$(pwd)/testing
utilsdir=$(pwd)/testing/utils
webdir=$(pwd)/testing/web

timestamp=$(date -d @$(git log -n1 --format="%ct") +%Y-%m-%d-%H%M)
gitstamp=$(make showversion)
version=${timestamp}-${gitstamp}
destdir=${basedir}/$(hostname)/${version}

echo ${version} ${destdir}

mkdir -p ${destdir}
log=${destdir}/log


# Rebuild/run; but only if previous attempt didn't crash badly.
if test -r ${destdir}/built.ok ; then
    echo "Skipping as ${destdir}/built.ok"
else
    make distclean 2>&1 | tee -a ${log}
    make kvm-install 2>&1 | tee -a ${log}
    make kvm-test 2>&1 | tee -a ${log}
    touch ${destdir}/built.ok
fi


# Always copy over the results
(
    (
	cd testing/pluto && tar cf - */OUTPUT
    ) | (
	cd ${destdir} && tar xpvf - && touch ${destdir}/tar.ok
    )
) 2>&1 | tee -a ${log}
test -r ${destdir}/tar.ok


(
    cd ${basedir}/$(hostname)/${version}
    # XXX: rundir gets used by json-summary to determine the directory
    # name :-(
    ${utilsdir}/json-results.py --rundir /${base}/$(hostname)/${version} */OUTPUT > table.json
    rm -f index.html
    # So that this directory is imune to later changes, just copy the
    # index page, along with all dependencies.
    cp ${webdir}/i3.html index.html
    cp -r ${basedir}/js ${destdir}
    touch ${destdir}/i3.ok
) 2>&1 | tee -a ${log}
test -r ${destdir}/i3.ok


: cd ${basedir}/$(hostname)
# This directory contains no html so generating json isn't very
# useful.
: # ${utilsdir}/json-summary.py --rundir . */table.json > table.new
: # ${utilsdir}/json-graph.py */table.json > graph.new
: mv old to new


(
    cd ${basedir}
    # XXX: this doesn't handle more than one host
    ${utilsdir}/json-summary.py --rundir $(hostname) */*/table.json > table.new
    ${utilsdir}/json-graph.py */*/table.json > graph.new
    for json in table graph ; do
	mv ${json}.new ${json}.json
    done
    touch ${destdir}/i1.ok
) 2>&1 | tee -a ${log}
test -r ${destdir}/i1.ok
