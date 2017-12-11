#!/bin/sh

if test $# -lt 1 ; then
    cat >> /dev/stderr <<EOF

Usage:

    $0 <gitrev> [ <repodir> ]

Dump <gitrev> from <repodir> as raw json using a format similar to:

    https://developer.github.com/v3/git/commits/

Notes:

missing: "parents", "tree", "url"

non-standard: "abbreviated_parent_hashes", "abbreviated_commit_hash",
"interesting", "subject".

EOF
    exit 1
fi

webdir=$(cd $(dirname $0) && pwd)
gitrev=$1 ; shift
if test $# -gt 0 ; then
    cd $1
    shift
fi

if ! git show --no-patch --format= ${gitrev} -- > /dev/null 2>&1 ; then
    echo "invalid: ${gitrev}" 1>&2
    exit 1
fi

key_format() {
    key=$1 ; shift
    format=$1 ; shift
    git show --no-patch --format=${format} ${gitrev} | \
	jq --raw-input \
	   --arg key $key \
	   '{ ($key): . }'
}

date_format() {
    key=$1 ; shift
    format=$1 ; shift
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
}

(
    # Convert the parent hashes into a list.

    for parent in $(git show --no-patch --format=%p "${gitrev}^{commit}") ; do
	echo ${parent} | jq --raw-input '.'
    done | jq -s '{ abbreviated_parent_hashes: . }'

    # Create the message, github seems to strip trailing new lines.

    #    git show --no-patch --format=%B ${gitrev} \
    #	| jq -s --raw-input \
    #	     '{ message: sub("\n\n$";""), }'

    # Add an "interesting" commit attribute.  Only "interesting"
    # commits get tested.
    #
    # git-interesting outputs either "false", "true" or "reason:
    # details" (for really interesting stuff).  Need to convert the
    # last one to proper json:

    interesting=$(${webdir}/git-interesting.sh ${gitrev})
    case "${interesting}" in
	*:* )
	    # convert 'reason: details' -> '"reason"'
	    interesting=$(echo ${interesting} | sed -e 's/\(.*\):.*/"\1"/')
	    ;;
    esac
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
