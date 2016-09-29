#!/bin/sh

if test $# -lt 2; then
    cat > /dev/stderr <<EOF

Usage:

    $0 <repodir> <summarydir>

Track <repodir>s current branch and test each "interesting" commit.
Publish results under <summarydir>.

EOF
    exit 1
fi

set -euvx

repodir=$(cd $1 && pwd) ; shift
summarydir=$(cd $1 && pwd) ; shift
webdir=$(dirname $0)
branch=$(${webdir}/gime-git-branch.sh ${repodir})
start=$(date -u -Iseconds)

# Make certain that origin is up-to-date.
${webdir}/git-fetch.sh ${repodir} || true

while true ; do

    # Start with the current top-of-tree, and then go forward
    # consuming any existing commits.
    #
    # The intent here is for a restart of this script to restart the
    # existing test run.
    while true ; do

	# Only run the testsuite and update the web site when the
	# current commit looks interesting.
	#
	# The heuristic is trying to identify coding and testsuite
	# changes; while ignoring infrastructure.
	if ${webdir}/git-interesting.sh ${repodir} HEAD ; then
	    ${webdir}/json-pending.sh \
		     --json ${summarydir}/pending.json \
		     ${repodir} ${branch}
	    ${webdir}/publish.sh ${repodir} ${summarydir}
	    ${webdir}/git-fetch.sh ${repodir} || true
	fi

	# If there is already a commit pending, advance to that.
	if ! ${webdir}/git-advance.sh ${repodir} ${branch} ; then
	    break
	fi

    done

    # Nothing new and interesting - the sequence git-fetch,
    # git-advance... has merged everything in - twiddle thumbs for a
    # few hours while waiting for the next change to come down the
    # pipe.
    while true ; do

	seconds=$(expr 60 \* 60 \* 3)
	now=$(date +%s)
	future=$(expr ${now} + ${seconds})
	date=$(date -Iseconds -u)
	${webdir}/json-status.sh \
		 --json ${summarydir}/status.json \
		 --job "testing branch ${branch}" \
		 --start "${start}" \
		 --date "${date}" \
		 "idle; will retry $(date -u -d @${future} +%H:%M)"
	sleep ${seconds}

	# Try again
	${webdir}/git-fetch.sh ${repodir} || true

	# Did the fetch pull in some new work?
	if ${webdir}/git-advance.sh ${repodir} ${branch} ; then
	    break
	fi
    done

done
