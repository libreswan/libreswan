#!/bin/sh

if test $# -lt 2; then
    cat <<EOF > /dev/stderr

Usage:

    $0 <repodir> <summarydir>

Build/run the testsuite in <repodir>.  Publish detailed results under
<summarydir>/<version>, and a summary under <summarydir>.

<version> is formed from the contaentation of the current checkout
date and "make showversion".

For instance:

    $0 . ~/results/master

EOF
    exit 1
fi

# exit if anything looks weird and be verbose.
set -euxv

repodir=$(cd $1 && pwd) ; shift
summarydir=$(cd $1 && pwd) ; shift

# where the scripts live
webdir=$(cd $(dirname $0) && pwd)
utilsdir=$(cd ${webdir}/../utils && pwd)

# Get the make-version, and then go backwards from that to determine
# the git:rev and git:date.
#
# Since later updates are going to use the same scripts, this helps to
# confirm that everything is working.
gitstamp=$(cd ${repodir} ; make showversion)
gitrev=$(${webdir}/gime-git-rev.sh ${gitstamp})
isodate=$(${webdir}/gime-git-date.sh ${repodir} ${gitrev})
date=$(echo ${isodate} \
	      | sed \
		    -e 's/T/-/' \
		    -e 's/^\([^:]*\):\([^:]*\).*$/\1\2/')

destdir=${summarydir}/${gitstamp}
echo ${destdir}

mkdir -p ${destdir}

# The status file needs to match status.js

rm -f ${summarydir}/progress.json
echo [] | jq --arg job ${gitstamp} \
	     '{ job: $job, log: [] }' \
	     > ${summarydir}/status.json

status() {
    jq --arg status "$*" \
       '.log += [{ date: (now|todateiso8601), status: $status }]' \
       < ${summarydir}/status.json \
       > ${summarydir}/status.new
    mv ${summarydir}/status.new ${summarydir}/status.json
}

status "started"


# Rebuild/run; but only if previous attempt didn't crash badly.
for target in distclean kvm-install kvm-retest kvm-shutdown ; do
    ok=${destdir}/make-${target}.ok
    status "run 'make ${target}'"
    if test ! -r ${ok} ; then
	( cd ${repodir} ; make ${target} )
	touch ${ok}
    fi
done


# Copy over all the tests.
status "copy test sources"
${webdir}/rsync-tests.sh ${repodir} ${destdir}


# Copy over all the results.
status "copy test results"
${webdir}/rsync-results.sh ${repodir} ${destdir}


# Generate the results page.
status "create results web page"
${webdir}/build-results.sh ${repodir} ${destdir}


# Generate the summary page.
status "update summary web page"
${webdir}/build-summary.sh ${repodir} ${summarydir} ${summarydir}/*/results.json


status "finished"
