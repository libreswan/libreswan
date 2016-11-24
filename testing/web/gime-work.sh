#!/bin/bash

if test $# -lt 2; then
  cat >> /dev/stderr <<EOF

Usage:

    $0 <summarydir> <repodir> [ <first-hash> ]

Print an untested commit hash on stdout.  The commit is selected by
looking for the first:

   - an untested merge point

   - an untested branch point

   - lognest untested run of commits (split)

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
point=
point_count=0
point_name=
run=""
count=0

while read hashes ; do
    count=$(expr ${count} + 1)
    hash=$(set -- ${hashes} ; echo $1)
    # Merge point? Save the first one.
    parents=$(cd ${repodir} && git show --no-patch --format=%p ${hash} | wc -w)
    if test ${parents} -gt 1 -a -z "${point_hash}" ; then
	point_hash=${hash}
	point_count=${count}
	point_name="merge-point"
	echo ${point_name} at ${point_count} with ${point_hash} 1>&2
	run=""
	continue
    fi
    # Branch point? Save the first one.
    children=$(set -- ${hashes} ; shift ; echo $@ | wc -w)
    if test ${children} -gt 1 -a -z "${point_hash}" ; then
	point_hash=${hash}
	point_count=${count}
	point_name="branch-point"
	echo ${point_name} at ${point_count} with ${point_hash} 1>&2
	run=""
	continue
    fi
    # already tested? stop the run
    if test -d ${summarydir}/*-g${hash}-* ; then
	# if this is longer, save it
	if test $(echo ${run} | wc -w) -gt $(echo ${longest} | wc -w) ; then
	    longest="${run}"
	    longest_count=${count}
	    echo longest-run $(echo ${longest} | wc -w) at ${longest_count} 1>&2
	fi
	run=""
	continue
    fi
    # Ignore uninteresting commits when looking for a run.
    if ! ${webdir}/git-interesting.sh ${repodir} ${hash} ; then
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

if test ${longest_count} -lt ${point_count} ; then
    # Split the run in approx two.
    print_selected "longest-run" $(echo ${longest} | awk '{ print $(NF / 2 + 1)}')
elif test ${point_count} -gt 0 ; then
    print_selected ${point_name} ${point_hash}
fi

exit 0
