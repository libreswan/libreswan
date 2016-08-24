#!/bin/sh

if test $# -lt 2; then
    cat > /dev/stderr <<EOF

Usage:

    $0 <repodir> <basedir>

Track <repodir>s current branch and test each "interesting" commit.
Publish results under <basedir>.

EOF
    exit 1
fi

set -euvx

repodir=$(cd $1 && pwd) ; shift
basedir=$(cd $1 && pwd) ; shift
webdir=$(dirname $0)
branch=$(${webdir}/gime-git-branch.sh ${repodir})

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
	if ${webdir}/git-interesting.sh ${repodir} ; then
	    ${webdir}/publish.sh ${repodir} ${basedir}
	fi

	# If there is already a commit pending, advance to that.
	if ! ${webdir}/git-advance.sh ${repodir} ${branch} ; then
	    break
	fi

    done

    # find some new commits
    while true ; do

	# poll the repo's origin, ignoring failures.
	${webdir}/git-fetch.sh ${repodir} || true

	# Did the fetch pull in some new work?
	if ${webdir}/git-advance.sh ${repodir} ${branch} ; then
	    break
	fi

	# Nothing new; twiddle thumbs for a few hours while we wait
	# for more changes to come down the pipe.
	seconds=$(expr 60 \* 60 \* 3)
	now=$(date +%s)
	future=$(expr ${now} + ${seconds})
	echo Currently: $(date -u -d @${now} +%H:%M)
	echo Sleeping until: $(date -u -d @${future} +%H:%M)
	sleep ${seconds}
    done

done
