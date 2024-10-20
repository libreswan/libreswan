#!/bin/bash

if test $# -lt 1; then
  cat >> /dev/stderr <<EOF

Usage:

    $0 <summarydir> [ <rutdir> [ <earliest_commit> ] ]

Iterate through [<earliest_commit>..HEAD] identifying the next next commit
to test.

On STDOUT, print the hash of the next commit to test.  The first of
the following is chosen:

  - <earliest_commit>, presumably it was specified for a reason

  - HEAD

  - a tag

  - a branch/merge point

  - when HEAD is "uninteresting", the most recent "interesting" commit

  - some other "interesting" commit selected by splitting the longest
    run of untested commits

On STDERR, in addition to random debug lines, list the status of all
commits using the format:

    {TESTED,UNTESTED}: <resultdir> <hash> <interesting> <index> <run-length> <bias>

(see git-interesting.sh for <interesting>'s value)
(see earliest-commit.sh for <earliest_commit>'s value)

EOF
  exit 1
fi

bindir=$(cd $(dirname $0) && pwd)

# <summarydir>
if test $# -gt 0 ; then
    summarydir=$(cd $1 && pwd) ; shift
else
    echo "Missing <summarydir>" 1>&2
    exit 1
fi

# <rutdir>
if test $# -gt 0 ; then
    rutdir=$1 ; shift
    cd ${rutdir} || {
	echo "could not change-directory to <rutdir> ${rutdir}" 1>&2
	exit 1
    }
else
    rutdir=.
fi

# <earliest_commit>
if test $# -gt 0 ; then
    earliest_commit=$(git rev-parse ${1}^{}) ; shift
else
    earliest_commit=$(${bindir}/earliest-commit.sh ${summarydir})
fi

echo summarydir=${summarydir} rutdir=${rutdir} earliest_commit=${earliest_commit} 1>&2

branch=$(${bindir}/gime-git-branch.sh .)
remote=$(git config --get branch.${branch}.remote)

echo branch=${branch} remote=${remote} 1>&2

# non-zero index indicates earliest commit is untested
earliest_index=0

# non-zero index indicates head is untested
head_commit=
head_index=0

# tag and branch/merge point; non-zero index indicates one was found

tag=
tag_commit=
tag_index=0

point=
point_commit=
point_index=0

# The longest untested run of commits.
#
# The RUN_BIAS (a count of TAG, MERGE and BRANCH commits) is used to
# perfer earlier shorter runs.
#
# non-zero index indicates an untested commit

declare -a run_commits run_indexes
run_commit=
run_index=0
run_length=0
run_bias=0

# Go through all the mainline commits (--first-parent excludes
# branches) in new-to-old order (--topo-order).
#
# revlist excludes earliest commit so add it

index=0

for commit in $(git rev-list \
		    --topo-order \
		    --first-parent \
		    ${earliest_commit}..${remote} ;
		echo ${earliest_commit}) ; do
    index=$(expr ${index} + 1)

    # See of the commit has a test result directory?
    #
    # Git's abbreviated hash length keeps growing.

    resultdir=
    for h in ${commit} \
		 $(expr ${commit} : '\(..............\).*') \
		 $(expr ${commit} : '\(.............\).*') \
		 $(expr ${commit} : '\(............\).*') \
		 $(expr ${commit} : '\(...........\).*') \
		 $(expr ${commit} : '\(..........\).*') \
		 $(expr ${commit} : '\(.........\).*') \
		 $(expr ${commit} : '\(........\).*') \
		 $(expr ${commit} : '\(.......\).*') \
	     ; do
	# either branch-count-g<hash> or tag-count-g<hash>-branch
	for d in ${summarydir}/*-g${h} ${summarydir}/*-g${h}-* ; do
	    if test -d "${d}" ; then
		resultdir=$d
		break
	    fi
	done
	if test -n "${resultdir}" ; then
	    break
	fi
    done

    # Always test HEAD (even when it isn't interesting).
    #
    # Hopefully this is less confusing then having tester.sh ignore new
    # commits.  These results will get pruned early.
    #
    # Use index=1 as a flag to indicate that the test wasn't tested.

    if test -z "${head_commit}" ; then
	head_commit=${commit}
	test ${index} -eq 1 # always true
	if test -z "${resultdir}" ; then
	    # flag that this hasn't been tested
	    head_index=${index}
	fi
	echo head ${head_commit} at ${head_index} 1>&2
	# Don't bail early as some scripts rely on this script
	# printing an analysis of all the commits.
    fi

    # deal with earliest_commit

    if test "${commit}" == "${earliest_commit}" ; then
	if test -z "${resultdir}" ; then
	    earliest_index=${index}
	fi
    fi

    # Find out how interesting the commit is, and why.  list the
    # results on stderr.
    #
    # Among other things, this output can be used to select a random
    # set of results to delete.  For instance, by selecting a random
    # subset of the less interesting results (interesting results have
    # a colon).  See README.txt.

    if interesting=$(${bindir}/git-interesting.sh ${rutdir} ${commit}) ; then
	uninteresting=false
    else
	uninteresting=true
    fi

    if test -n "${resultdir}"; then
	TESTED=TESTED
    else
	TESTED=UNTESTED
    fi

    echo ${TESTED}: ${resultdir} ${commit} ${interesting} ${index} ${#run_commits[@]} ${run_bias} 1>&2

    # Skip uninteresting commits - don't include them in untested
    # runs.

    if ${uninteresting} ; then
	continue
    fi

    # Update the longest run if, after using the RUN_BIAS to bias
    # things towards earlier runs, it is longer.  While repeatedly
    # updating isn't the most efficient it avoids the need to do
    # updates in the various code paths below.

    if test ${#run_commits[@]} -gt $(expr ${run_length} + ${run_bias}) ; then
	run_length=${#run_commits[@]}
	i=$((run_length / 2))
	run_index=${run_indexes[$i]}
	run_commit=${run_commits[$i]}
	echo RUN ${run_commit} at ${run_index} length ${run_length} commits "${run_commits[@]}" indexes "${run_indexes[@]}" 1>&2
    fi

    # Increment the point count (branch, merge, tag) when needed.
    #
    # Do this before discarding tested commits so that tested TAG,
    # BRANCH, and MERGE commits are included in the count.
    #
    # The RUN_BIAS is used to bias the untested run length so that
    # earlier shorter runs are preferred.

    case "${interesting}" in
	*:* )
	    run_bias=$(expr ${run_bias} + 1)
	    echo bias: ${run_bias} ${commit} ${interesting} at ${index} 1>&2
	    ;;
    esac

    # already tested? stop the current run and start again

    if test -n "${resultdir}"; then
       	unset run_commits ; declare -a run_commits
	continue
    fi

    # Finally, save the first really interesting TAG or BRANCH/MERGE
    # commit.

    case "${interesting}" in
	tag:*)
	    if test -z "${tag}" ; then
	       tag=$(expr "${interesting}" : '.*: *\(.*\)')
	       tag_commit=${commit}
	       tag_index=${index}
	    fi
	    # kill current run
	    unset run_commits ; declare -a run_commits
	    continue
	    ;;
	branch:* | merge:* )
	    if test -z "${point}" ; then
		point=$(expr "${interesting}" : '\(.*\):')
		point_commit=${commit}
		point_index=${index}
	    fi
	    # kill current run
	    unset run_commits ; declare -a run_commits
	    continue
	    ;;
    esac

    # append commit to the end of run_commits[] and run_indexes[]
    # arrays, growing them by one.
    i=${#run_commits[@]}
    run_indexes[$i]=${index}
    run_commits[$i]=${commit}

done

# Dump the results
# ${point^^} converts ${point} to upper case

echo EARLIEST ${earliest_commit} at ${earliest_index} 1>&2
echo HEAD ${head_commit} at ${head_index} 1>&2
echo ${point^^}POINT ${point_commit} at ${point_index} 1>&2
echo TAG ${tag} ${tag_commit} at ${tag_index} 1>&2
echo RUN ${run_commit} at ${run_index} length ${run_length} 1>&2

# Now which came first?

print_selected() {
    echo selecting $1 at $2 1>&2
    ( git log $2^..$2 ) 1>&2
    echo $2
    exit 0
}

# earliest
if test "${earliest_index}" -gt 0 ; then
    print_selected earliest "${earliest_commit}"
fi

# head
if test ${head_index} -gt 0 ; then
    print_selected "head" ${head_commit}
fi

# any tag
if test "${tag_index}" -gt 0 ; then
    print_selected tag:${tag} "${tag_commit}"
fi

# any branch/merge is untested?
if test "${point_index}" -gt 0 ; then
    print_selected ${point} "${point_commit}"
fi

if test ${run_index} -gt 0 ; then
    print_selected "longest-run" ${run_commit}
fi

exit 1
