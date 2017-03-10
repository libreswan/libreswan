#!/bin/sh

if test $# -lt 2; then
    cat >> /dev/stderr <<EOF

Usage:

    $0 <repodir> <summarydir>

Build/run the testsuite in <repodir>.  Publish detailed results under
<summarydir>/<version>, and a summary under <summarydir>.

<version> is determined by "git describe" with some twists.

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
#
# The format is: VERSION[-OFFSET-gHASH][-dirty]-BRANCH
#
# When on a tag, "git describe" (which "make showversion" uses) leaves
# out OFFSET-gHASH) so, if missing, patch that up.

gitstamp=$(cd ${repodir} ; make showversion)
case ${gitstamp} in
    *-g*-* )
	echo 'VERSION-OFFSET-gHASH[-dirty]-BRANCH'
	;;
    * )
	echo 'VERSION[-dirty]-BRANCH'
	gitrev=$(cd ${repodir} ; git show --no-patch --format=%h)
	gitstamp=$(echo ${gitstamp} | sed -e "s/-/-0-g${gitrev}-/")
	;;
esac
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


# Just do everything, always.

for target in kvm-shutdown distclean kvm-install kvm-keys kvm-test kvm-shutdown; do
    # delete ok as kvm-shutdown appears twice
    ok=${destdir}/${target}.ok
    rm -f ${ok}
    status "run 'make ${target}'"
    # Because this make is in a pipeline its status is missed, get
    # around it by testing for ok.  Need to avoid passing anything
    # that might contain a quote (like the subject) to the awk script.
    (
	make -C ${repodir} ${target} && touch ${ok}
    ) 2>&1 | if test -r ${webdir}/${target}-status.awk ; then
	awk -v script="${script}" -f ${webdir}/${target}-status.awk
    else
	cat
    fi | tee -a ${destdir}/${target}.log
    if test ! -r ${ok}; then
	status "run 'make ${target}' died"
	# Abort, while presumably it is just the build dieing it could
	# be something else.
	exit 1
    fi
done


# XXX: Can't use "make kvm-publish" here - it probably doesn't exist
# in the source code.

# Copy over all the tests.
status "copy test sources"
${webdir}/rsync-tests.sh ${repodir} ${destdir}


# Copy over all the results.
status "copy test results"
${webdir}/rsync-results.sh ${repodir} ${destdir}


# Generate the results page.
status "create results web page"
${webdir}/build-results.sh ${repodir} ${repodir}/testing/pluto ${destdir}


# Always compress the log files; but not the output from make.
status "compressing log files"
find ${destdir} -path '*/OUTPUT/*.log' -type f -print0 | xargs -0 -r bzip2 -9 -v


status "finished"
