#!/bin/sh

if test $# -lt 1 ; then
    cat >> /dev/stderr <<EOF

Usage:

    $0 <gitrev> [ <repodir> ]

Dump <gitrev> from <repodir> as raw json using a format similar to:

    https://developer.github.com/v3/git/commits/

Where:

    included:
        author
        committer

    missing:
        sha (see hash)
        tree
        url
        verification
        message (see subject)
	parents (see parent_hashes)

    non-standard:
        hashes
        parent_hashes
	interesting
	subject

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
    git show --no-patch --format="${format}" ${gitrev} | \
	jq --raw-input \
	   --arg key "$key" \
	   '{ ($key): . }'
}

commiter_format() {
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
    # Output the parent commits as a list.
    #
    # %P puts all the hashes on a single line separated by spaces, the
    # %for-loop converts that to one hash per line.  Change it to sed
    # %...?

    for parent in $(git show --no-patch --format=%P "${gitrev}^{commit}") ; do
	echo ${parent} | jq --raw-input '.'
    done | jq -s '{ parent_hashes: . }'

    # Create the message, github seems to strip trailing new lines.
    #
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
    key_format hash %H

    commiter_format author a
    commiter_format committer c

) | jq -s 'add'
