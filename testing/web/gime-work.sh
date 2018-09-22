#!/bin/bash

if test $# -lt 1; then
  cat >> /dev/stderr <<EOF

Usage:

    $0 <summarydir> [ <repodir> [ <first-commit> ] ]

Select, and then print on STDOUT, the hash for an untested commit in
the range [<first-commit>..HEAD].

First choice is HEAD; second choice is something "interesting" such as
a tag or branch (see git-interesting.sh); and the third choice is to
split the longest run of untested commits.

Additional debugging information is printed on STDER including lines
of the form:

    TESTED: <resultdir> <hash> <interesting>

which can be used to examine result directories.

EOF
  exit 1
fi

webdir=$(cd $(dirname $0) && pwd)

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
fi

# <first-commit>
if test $# -gt 0 ; then
    first_commit=$1 ; shift
else
    first_commit=$(${webdir}/earliest-commit.sh ${summarydir})
fi
first_commit=$(git show --no-patch --format=%H ${first_commit})

branch=$(${webdir}/gime-git-branch.sh .)
remote=$(git config --get branch.${branch}.remote)

# Find the longest untested run of commits.

run=""
count=0

head_commit=
head_count=0

points="tag merge branch"
for point in ${points} ; do
    point_commit=${point}_commit
    point_count=${point}_count
    eval ${point_commit}=
    eval ${point_count}=0
done

longest_bias=0
longest_length=0
longest_count=0
longest_commit=

while read commits ; do
    count=$(expr ${count} + 1)
    commit=$(set -- ${commits} ; echo $1)

    # directory containing test result?
    #
    # Git seems to use both 7 and 9 character abbreviated hashes.  Try
    # both.

    resultdir=
    for h in ${commit} $(expr ${commit} : '\(.......\).*') $(expr ${commit} : '\(.........\).*') ; do
	d=$(echo ${summarydir}/*-g${h}-* | awk '{print $1}')
	if test -d "$d" ; then
	    resultdir=$d
	    break
	fi
    done

    # Always test HEAD (even when it isn't interesting).
    #
    # Hopefuly this is less confusing then having tester.sh ignore new
    # commits.  These results will get pruned early.
    #
    # Use count=1 as a flag to indicate that the test wasn't tested.

    if test -z "${head_commit}" ; then
	head_commit=${commit}
	test ${count} -eq 1 # always true
	if test -z "${resultdir}" ; then
	    # flag that this hasn't been tested
	    head_count=${count}
	fi
	echo head ${head_commit} at ${head_count} 1>&2
	# Don't bail early as some scripts rely on this script
	# printing an analysis of all the commits.
    fi

    # Find out how interesting the commit is; and why.

    if interesting=$(${webdir}/git-interesting.sh ${commit}) ; then
	uninteresting=false
    else
	uninteresting=true
    fi

    # List all the tested commits.
    #
    # Among other things, this output can be used to select a random
    # set of results to delete.  For instance, by selecting a random
    # subset of the less interesting results (interesting results have
    # a colon).  See README.txt.

    if test -n "${resultdir}"; then
	echo TESTED: ${resultdir} ${commit} ${interesting} 1>&2
    fi

    # Skip uninteresting commits; don't include them in untested runs.

    if ${uninteresting} ; then
	continue
    fi

    # Update the longest run if, after adjusting for a bias towards
    # earlier runs, it is longer; while repeatedly updating isn't the
    # most efficient it avoids the need to do updates in the various
    # code paths below.

    run_length=$(echo ${run} | wc -w)
    if test ${run_length} -gt $(expr ${longest_length} + ${longest_bias}) ; then
	longest_length=${run_length}
	longest_count=${count}
	longest_commit=$(echo ${run} | awk '{ print $(NF / 2 + 1)}')
	echo longest ${longest_commit} at ${longest_count} length ${longest_length} bias ${longest_bias} run ${run} 1>&2
    fi

    # If this is a really interesting commit (branch, merge, tag),
    # increment the bias so that earlier runs are preferred.  Do this
    # before discarding tested commits so that nothing is missed.
    # This somewhat double counts as both merge and branch points are
    # considered.

    case "${interesting}" in
	*:* )
	    longest_bias=$(expr ${longest_bias} + 1)
	    echo bias ${longest_bias} $(echo ${interesting} | cut -d: -f1) ${commit} at ${count} 1>&2
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
	*:* )
	    point=$(expr "${interesting}" : '\(.*\):')
	    point_commit=${point}_commit
	    point_count=${point}_count
	    if test -z "${!point_commit}" ; then
		eval ${point_commit}=${commit}
		eval ${point_count}=${count}
		echo "${point} ${!point_commit} at ${!point_count}" 1>&2
		run=""
		continue
	    fi
	    ;;
    esac

    run="${run} ${commit}"

done < <(git rev-list \
	     --topo-order \
	     --children \
	     ${first_commit}..${remote} ; echo ${first_commit})

# Dump the results

echo HEAD ${head_commit} at ${head_count} 1>&2
for point in ${points} ; do
    point_commit=${point}_commit
    point_count=${point}_count
    echo "${point^^} ${!point_commit} at ${!point_count}" 1>&2
done
echo LONGEST ${longest_length} ${longest_count} ${longest_commit} 1>&2

# Now which came first?

print_selected() {
    echo selecting $1 at $2 1>&2
    ( git show --no-patch $2 ) 1>&2
    echo $2
    exit 0
}

if test ${head_count} -gt 0 ; then
    print_selected "head" ${head_commit}
fi

for point in ${points} ; do
    point_commit=${point}_commit
    point_count=${point}_count
    if test "${!point_count}" -gt 0 -a "${!point_count}" -lt "${longest_count}" ; then
	print_selected ${point} "${!point_commit}"
    fi
done

if test ${longest_count} -gt 0 ; then
    # Split the run in approx two.
    print_selected "longest-run" ${longest_commit}
fi

exit 1
