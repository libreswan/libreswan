#!/bin/sh

if test $# -lt 1 ; then
    cat >> /dev/stderr <<EOF

Usage:

    $0 <repdir> <gitrev>

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

bindir=$(cd $(dirname $0) && pwd)
# switch to repodir
cd $1 ; shift
gitrev=$1 ; shift

if ! git log --format= ${gitrev}^..${gitrev} -- > /dev/null 2>&1 ; then
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
    # The parents are all on one line so split it.

    for parent in $(${bindir}/gime-git-parents.sh . ${gitrev}) ; do
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

    interesting=$(${bindir}/git-interesting.sh . ${gitrev})
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
