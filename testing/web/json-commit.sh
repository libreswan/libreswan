#!/bin/sh

if test $# -lt 2 ; then
    cat >> /dev/stderr <<EOF

Usage:

    $0 [ --json <json> ] <repodir> <gitrev> ...

Dump <gitrev>... from <repodir> as raw json.

If <json> is specified, write the json into that file as a json
array.

EOF
    exit 1
fi

webdir=$(dirname $0)

json=
while test $# -gt 0 ; do
    case $1 in
	--json )
	    shift ; json=$1 ; shift
	    ;;
	-* )
	    echo "Unknown option: $*" 1>&2
	    exit 1
	    ;;
	* )
	    break
	    ;;
    esac
done
repodir=$1 ; shift

key_format() (
    key=$1 ; shift
    format=$1 ; shift
    cd ${repodir}
    git show --no-patch --format=${format} ${gitrev} | \
	jq --raw-input \
	   --arg key $key \
	   '{ ($key): . }'
)

for gitrev in "$@" ; do

    (
	jq --null-input \
	   --argjson rank "$(${webdir}/gime-git-rank.sh ${repodir} ${gitrev})" \
	   '{ rank: $rank }'

	# Convert the parent hashes into a list.

	${webdir}/gime-git-parents.sh ${repodir} ${gitrev} | \
	    jq --raw-input '.' | \
	    jq -s '{ abbreviated_parent_hashes: . }'

	# Convert the body to a list.  Need to strip the trailing
	# blank line.  Fortunately it seems that the output from %b
	# always contains at least one trailing blank line.

	( cd ${repodir} ; git show --no-patch --format=%b ${gitrev} ) | \
	    jq --raw-input \
	       '{ body: ([., inputs] | if .[-1] == "" then .[0:-1] else . end) }'

	# Add an "interesting" commit attribute.  Only "interesting"
	# commits get tested.

	if ${webdir}/git-interesting.sh ${repodir} ${gitrev} ; then
	    echo true
	else
	    echo false
	fi | jq '{ interesting: . }'

	# Rest are easy to deal with.

	key_format abbreviated_commit_hash %h
	key_format author_date %aI
	key_format author_name %an
	key_format author_email %ae
	key_format committer_date %cI
	key_format committer_name %cn
	key_format committer_email %ce
	key_format subject %s

    ) | jq -s 'add'

done | \
    if test -n "${json}" ; then
	jq -s '.' > ${json}.tmp
	mv ${json}.tmp ${json}
    else
	cat
    fi
