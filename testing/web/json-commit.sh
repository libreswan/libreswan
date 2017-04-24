#!/bin/sh

if test $# -lt 2 ; then
    cat >> /dev/stderr <<EOF

Usage:

    $0 [ --json <json> ] <repodir> <gitrev> ...

Dump <gitrev>... from <repodir> as raw json using a format similar to:

    https://developer.github.com/v3/git/commits/

Notes:

"parents" is missing (use non-standard abbreviated_parent_hashes);
"tree" is missing; "url" is missing; "abbreviated_commit_hash" is non
standard; "rank" is non-standard; "interesting" is non-standard;
"subject" is non-standard.

If <json> is specified, then write the json into that file as a json
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

date_format() (
    key=$1 ; shift
    format=$1 ; shift
    cd ${repodir}
    git show --no-patch --format=%${format}I%n%${format}n%n%${format}e ${gitrev} \
	| jq --raw-input . \
	| jq -s \
	     --arg key $key \
	     '{
    ($key): {
        date: .[0],
        name: .[1],
        email: .[2],
    },
}'
)

echo -n 'Processing:' 1>&2
for gitrev in "$@" ; do
    if ( cd ${repodir} && git show --no-patch --format= ${gitrev} -- > /dev/null 2>&1 ); then
	echo -n " ${gitrev}" 1>&2
    else
	echo -n " invalid:${gitrev}" 1>&2
	continue
    fi
    (

	jq --null-input \
	   --argjson rank "$(${webdir}/gime-git-rank.sh ${repodir} ${gitrev})" \
	   '{ rank: $rank }'

	# Convert the parent hashes into a list.

	${webdir}/gime-git-parents.sh ${repodir} ${gitrev} | \
	    jq --raw-input '.' | \
	    jq -s '{ abbreviated_parent_hashes: . }'

	# Create the message, github seems to strip trailing new
	# lines.

	( cd ${repodir} ; git show --no-patch --format=%B ${gitrev} ) \
	    | jq -s --raw-input \
		 '{ message: sub("\n\n$";""), }'

	# Add an "interesting" commit attribute.  Only "interesting"
	# commits get tested.
	#
	# git-interesting outputs "reason: details" for really
	# interesting stuff, "true" for patches, and nothing
	# otherwise.  Need to convert that to proper json.

	if interesting=$(${webdir}/git-interesting.sh ${repodir} ${gitrev}) ; then
	    # 'reason: details' -> '"reason"'
	    interesting=$(echo ${interesting} | sed -e 's/\(.*\):.*/"\1"/')
	else
	    interesting=false
	fi
	jq --null-input \
	   --argjson interesting "${interesting}" \
	   '{ interesting: $interesting }'

	# Rest are easy to deal with.

	key_format subject %s
	key_format sha %H
	key_format abbreviated_commit_hash %h

	date_format author a
	date_format committer c

    ) | jq -s 'add'
done | \
    if test -n "${json}" ; then
	jq -s '.' > ${json}.tmp
	mv ${json}.tmp ${json}
    else
	cat
    fi
echo "" 1>&2
