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

status_make() {
    status "run 'make $@'"
    make -C ${repodir} "$@"
}

for target in distclean kvm-install kvm-keys ; do
    ok=${destdir}/${target}.ok
    if test ! -r "${ok}" ; then
	status_make ${target}
	touch ${ok}
    fi
done


# Because the make is in a pipeline its status is missed, get around
# it by testing for ok.

ok=${destdir}/make-kvm-test.ok
if test ! -r "${ok}" ; then
    # Need to avoid passing anything that might contain a quote (like
    # the subject).
    (
	status_make kvm-test
	touch ${ok}
    ) | awk -v script="${script}" -f ${webdir}/publish-status.awk
    test -r ${destdir}/make-kvm-test.ok
fi


# always shutdown
status_make kvm-shutdown


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
