#!/bin/bash

if test $# -lt 2; then
  cat >> /dev/stderr <<EOF

Usage:

    $0 <summarydir> <repodir> [ <first-hash> ]

Print an untested commit hash on stdout.  The commit is selected by
looking for the first:

   - HEAD

   - an untested merge point

   - an untested branch point

   - longest untested run of commits (split)

EOF
  exit 1
fi

webdir=$(dirname $0)

summarydir=$1 ; shift
repodir=$1 ; shift
if test $# -gt 0 ; then
    start_hash=$1 ; shift
else
    start_hash=$(${webdir}/earliest-commit.sh ${repodir} ${summarydir})
    echo start-hash: ${start_hash} 1>&2
fi

branch=$(${webdir}/gime-git-branch.sh ${repodir})
remote=$(${webdir}/gime-git-remote.sh ${repodir} ${branch})

print_selected() {
    echo selecting: $1 1>&2
    ( cd ${repodir} && git show --no-patch $2 ) 1>&2
    echo $2
}

# Find the longest untested run of commits.

longest=""
longest_count=0
point_hash=
point_count=0
point_name=
head_hash=""
head_count=0
run=""
count=0

while read hashes ; do
    count=$(expr ${count} + 1)
    hash=$(set -- ${hashes} ; echo $1)
    # Save the first interesting HEAD commit; there must be one.
    if test -z "${head_hash}" && ${webdir}/git-interesting.sh ${repodir} ${hash} > /dev/null ; then
	head_hash=${hash}
	head_count=${count}
	echo head ${head_hash} at ${head_count} 1>&2
    fi
    # already tested? stop the current run and start again
    if test -d $(echo ${summarydir}/*-g${hash}-* | awk '{print $1}'); then
	# if this is longer, save it
	if test $(echo ${run} | wc -w) -gt $(echo ${longest} | wc -w) ; then
	    longest="${run}"
	    longest_count=${count}
	    echo longest $(echo ${longest} | wc -w) at ${longest_count} 1>&2
	fi
	run=""
	continue
    fi
    # Save the first untested merge/branch point.
    #
    # The above will have already skipped over tested merge/branch
    # points.  Restart RUN since this breaks the run.
    if test -z "${point_hash}" ; then
	parents=$(${webdir}/gime-git-parents.sh ${repodir} ${hash} | wc -l)
	if test ${parents} -gt 1 ; then
	    point_hash=${hash}
	    point_count=${count}
	    point_name="merge-point"
	    echo ${point_name} ${point_hash} at ${point_count} 1>&2
	    run=""
	    continue
	fi
	children=$(${webdir}/gime-git-children.sh ${repodir} ${hash} | wc -l)
	if test ${children} -gt 1 ; then
	    point_hash=${hash}
	    point_count=${count}
	    point_name="branch-point"
	    echo ${point_name} ${point_hash} at ${point_count} 1>&2
	    run=""
	    continue
	fi
    fi
    # Ignore uninteresting commits when looking for a run.
    if ! ${webdir}/git-interesting.sh ${repodir} ${hash} > /dev/null ; then
	# don't include uninteresting commits
	continue
    fi
    run="${run} ${hash}"
done < <(${webdir}/gime-git-revisions.sh \
		  ${repodir} \
		  --topo-order \
		  --children \
		  ${start_hash}..${remote})

# Now which came first?

if test ${head_count} -gt 0 \
	-a ${head_count} -lt ${longest_count} \
	-a ${head_count} -lt ${point_count} \
	-a ! -d ${summarydir}/*-g${head_hash}-* ; then
    print_selected "HEAD" ${head_hash}
elif test ${point_count} -gt 0 \
	  -a ${point_count} -lt ${longest_count} ; then
    print_selected ${point_name} ${point_hash}
elif test ${longest_count} -gt 0 ; then
    # Split the run in approx two.
    print_selected "longest-run" $(echo ${longest} | awk '{ print $(NF / 2 + 1)}')
fi

exit 0
