#!/bin/bash

if test $# -lt 1; then
  cat >> /dev/stderr <<EOF

Usage:

    $0 <summarydir> [ <repodir> [ <earliest_commit> ] ]

Iterate through [<earliest_commit>..HEAD] identifying the next next commit
to test.

On STDOUT, print the hash of the next commit to test.  The first of
the following is chosen:

  - <earliest_commit>
    presumably it was specified for a reason

  - HEAD

  - a tag

  - a branch/merge point

  - an "interesting" commit selected by splitting the longest run of
    untested commits

On STDERR, in addition to random debug lines, list the status of all
commits using the format:

    (TESTED|UNTESTED): <resultdir> <hash> <interesting> <index> <run-length> <bias>

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

# <repodir>
if test $# -gt 0 ; then
    repodir=$1 ; shift
    cd ${repodir} || {
	echo "could not change-directory to <repodir> ${repodir}" 1>&2
	exit 1
    }
else
    repodir=.
fi

# <earliest_commit>
if test $# -gt 0 ; then
    earliest_commit=$(git rev-parse ${1}^{}) ; shift
else
    earliest_commit=$(${bindir}/earliest-commit.sh ${summarydir})
fi

branch=$(${bindir}/gime-git-branch.sh .)
remote=$(git config --get branch.${branch}.remote)

# Find the longest untested run of commits.  Use a bias to prefer
# earlier runs.

run=""
index=0
point_count=0

# non-zero index indicates untested
earliest_index=0

# non-zero index indicates untested
head_commit=
head_index=0

longest_commit=
longest_index=0
longest_length=0

tag=
tag_commit=
tag_index=0

point=
point_commit=
point_index=0
point_rank=0

while read commits ; do
    index=$(expr ${index} + 1)
    commit=$(set -- ${commits} ; echo $1)

    # See of the commit has a test result directory?
    #
    # Git's idea of how long an abrievated hash is keeps growing.

    resultdir=
    for h in ${commit} \
		 $(expr ${commit} : '\(.............\).*') \
		 $(expr ${commit} : '\(............\).*') \
		 $(expr ${commit} : '\(...........\).*') \
		 $(expr ${commit} : '\(..........\).*') \
		 $(expr ${commit} : '\(.........\).*') \
		 $(expr ${commit} : '\(........\).*') \
		 $(expr ${commit} : '\(.......\).*') \
	     ; do
	d=$(echo ${summarydir}/*-g${h}-* | awk '{print $1}')
	if test -d "$d" ; then
	    resultdir=$d
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

    if interesting=$(${bindir}/git-interesting.sh ${repodir} ${commit}) ; then
	uninteresting=false
    else
	uninteresting=true
    fi

    run_length=$(echo ${run} | wc -w)
    if test -n "${resultdir}"; then
	TESTED=TESTED
    else
	TESTED=UNTESTED
    fi
    echo ${TESTED}: ${resultdir} ${commit} ${interesting} ${index} ${run_length} ${point_count} 1>&2

    # Skip uninteresting commits - don't include them in untested
    # runs.

    if ${uninteresting} ; then
	continue
    fi

    # Update the longest run if, after using the POINT_COUNT to bias
    # things towards earlier runs, it is longer.  While repeatedly
    # updating isn't the most efficient it avoids the need to do
    # updates in the various code paths below.

    if test ${run_length} -gt $(expr ${longest_length} + ${point_count}) ; then
	longest_length=${run_length}
	longest_index=${index}
	longest_commit=$(echo ${run} | awk '{ print $(NF / 2 + 1)}') # midpoint
	echo longest ${longest_commit} at ${longest_index} length ${longest_length} run ${run} 1>&2
    fi

    # Increment the point count (branch, merge, tag) when needed.
    #
    # Do this before discarding tested commits so that nothing is
    # missed.
    #
    # The POINT_COUNT is used to bias the untested run length that
    # earlier shorter runs are preferred.

    case "${interesting}" in
	*:* )
	    point_count=$(expr ${point_count} + 1)
	    echo point: ${point_count} $(echo ${interesting} | cut -d: -f1) ${commit} at ${index} 1>&2
	    ;;
    esac

    # already tested? stop the current run and start again

    if test -n "${resultdir}"; then
	run=""
	continue
    fi

    # Finally, save the first really interesting (as in branch, merge,
    # or tag) untested commit.

    case "${interesting}" in
	tag:*)
	    tag=$(expr "${interesting}" : '.*: *\(.*\)')
	    tag_commit=${commit}
	    tag_index=${index}
	    # kill current run
	    run=""
	    continue
	    ;;
	*:* )
	    point=$(expr "${interesting}" : '\(.*\):')
	    point_commit=${commit}
	    point_index=${index}
	    point_rank=${point_count}
	    # kill current run
	    run=""
	    continue
	    ;;
    esac

    run="${run} ${commit}"

done < <(git rev-list \
	     --topo-order \
	     --children \
	     ${earliest_commit}..${remote} ; echo ${earliest_commit})

# Dump the results
# ${point^^} converts ${point} to upper case

echo HEAD ${head_commit} at ${head_index} 1>&2
echo ${point^^}POINT ${point_commit} at ${point_index} rank ${point_rank} 1>&2
echo TAG ${tag} ${tag_commit} at ${tag_index} 1>&2
echo LONGEST ${longest_commit} at ${longest_index} length ${longest_length} 1>&2
echo EARLIEST ${earliest_commit} at ${earliest_index} 1>&2

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

if test ${longest_index} -gt 0 ; then
    print_selected "longest-run" ${longest_commit}
fi

exit 1
