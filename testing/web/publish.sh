#!/bin/sh

if test $# -lt 2; then
    cat >> /dev/stderr <<EOF

Usage:

    $0 <repodir> <summarydir>

Build/run the testsuite in <repodir>.  Publish detailed results under
<summarydir>/<version>, and a summary under <summarydir>.

<version> is determined by "make showversion".

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

destdir=${summarydir}/${gitstamp}
echo ${destdir}

mkdir -p ${destdir}

# The status file needs to match status.js; note the lack of quotes
# qhen invoking ${script}.  This is matches the unqoted line that gets
# invoked by the awk script further down.

start=$(date -u -Iseconds)
script="${webdir}/json-status.sh \
  --json ${summarydir}/status.json \
  --commit ${repodir} ${gitrev} \
  --start ${start}"
status() {
    ${script} --date $(date -u -Iseconds) " ($*)"
}

status "started"


# If not already done, set up for a test run.

force=false
for target in distclean kvm-install kvm-keys kvm-test kvm-shutdown; do
    ok=${destdir}/${target}.ok
    if test ! -r "${ok}" || ${force} ; then
	force=true
	status "run 'make ${target}'"
	if test -r ${webdir}/${target}-status.awk ; then
	    # Because this make is in a pipeline its status is missed,
	    # get around it by testing for ok.  Need to avoid passing
	    # anything that might contain a quote (like the subject)
	    # to the awk script.
	    (
		make -C ${repodir} ${target}
		touch ${ok}
	    ) | awk -v script="${script}" -f ${webdir}/${target}-status.awk
	else
	    make -C ${repodir} ${target}
	    touch ${ok}
	fi
	test -r ${ok}
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


status "finished"
