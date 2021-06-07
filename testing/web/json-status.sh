#!/bin/sh

if test $# -lt 1 ; then
    cat >> /dev/stderr <<EOF

Usage:

    $0 [ --json <json> ] [ --directory <directory> ] <details> ...

Update the <json> file with the current status.  Multiple <details>
are allowed and are appended.

If --commit <repo> <rev> is specified, then <details> and <job> are
set based on that commit.

By default, raw json is written to stdout.

EOF
    exit 1
fi

bindir=$(cd $(dirname $0) && pwd)

details=
sp=
json=
while test $# -gt 0; do
    case $1 in
	--json ) shift ; json=$1 ; shift ;;
	--directory ) shift ; directory=$1 ; shift ;;
	-* ) echo "Unrecognized option: $*" >/dev/stderr ; exit 1 ;;
	* ) details="${details}${sp}$1" ; sp=" " ; shift ;;
    esac
done


cat <<EOF 1>&2

--------------------------------------

    ${details}

--------------------------------------

EOF

{
    jq --null-input \
       --arg details "${details}" \
       --arg directory "${directory}" \
       '
if ($directory|length) > 0 then { directory: $directory } else {} end
| .date = (now|todateiso8601)
| .details = $details
'
} | {
    if test -n "${json}" ; then
	cat > ${json}.tmp
	mv ${json}.tmp ${json}
    else
	cat
    fi
}
