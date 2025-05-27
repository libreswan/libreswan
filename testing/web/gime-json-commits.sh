#!/bin/bash


if test $# -lt 1; then
  cat >> /dev/stderr <<EOF

Usage:

    $0 <summarydir> [ <rutdir> [ <earliest_commit> ] ]

Iterate through [<earliest_commit>..HEAD] dumping minimal JSON on
each.
EOF
  exit 1
fi

bindir=$(cd $(dirname $0) && pwd)
summarydir=$(realpath $1) ; shift
rutdir=$(realpath $1) ; shift
earliest_commit=$1 ; shift

# HEAD may not be latest commit; figure out what it is
branch=$(${bindir}/gime-git-branch.sh ${rutdir}) # main master ...
remote=$(git -C ${rutdir} config --get branch.${branch}.remote) # origin/ libreswan/ ...
latest_commit=${remote}/${branch}

rank=0

{
    # start at latest; stop at one commit previous to commit after
    # earliest_commit, i.e., earliest_commit
    #
    # Dump both the author's and the committer's dates; the author's
    # date is used when showing the commit and the committer's date is
    # used when working out where to plot the commit on the progress
    # graph.  When an old commit is cherry-picked or merged, the two
    # can differ wildly.
    #
    # Also include the rank numbered in descending order.
    git -C ${rutdir} log \
	--format='%H,%h,%(decorate:prefix=,suffix=,separator= ,pointer=>,tag=tag:),%P,%aI,%cI,%s' \
	${latest_commit} ^${earliest_commit}^
} | {
    while IFS=, read hash abbrev_hash tags parents author_date committer_date subject ; do
	printf '{'
	printf ' '
	printf '"hash": "%s"' "${hash}"
	printf ', '
	printf '"abbrev_hash": "%s"' "${abbrev_hash}"
	printf ', '
	printf '"author_date": "%s"' "${author_date}"
	printf ', '
	printf '"committer_date": "%s"' "${committer_date}"
	printf ', '
	printf '"tags": "%s"' "${tags}"
	printf ', '
	printf '"rank": %d' "${rank}" # yes, integer!
	printf ', '
	printf '"parents": ['
	fs=' '
	for parent in ${parents} ; do
	    printf '%s"%s"' "${fs}" "${parent}"
	    fs=', '
	done
	printf ' ]'
	printf ', '
	printf ' "subject": "%s"' "$(printf '%s\n' "${subject}" | sed -e 's;";\\";g')"
	printf ' '
	printf '}\n'
	rank=$((rank + 1))
    done
}
