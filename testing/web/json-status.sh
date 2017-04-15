#!/bin/sh

if test $# -lt 1 ; then
    cat >> /dev/stderr <<EOF

Usage:

    $0 [ --json <json> ] [ --directory <directory> ] [ --commit <repo> <rev> | --job <job> ] --start <start> --date <date> [ <details> ... ]

Update the <json> file with the current status.  Multiple <details>
are allowed and are appended.

If --commit <repo> <rev> is specified, then <details> and <job> are
set based on that commit.

By default, raw json is written to stdout.

EOF
    exit 1
fi

webdir=$(cd $(dirname $0) && pwd)

details=
json=
hash=
while test $# -gt 0; do
    case $1 in
	--json ) shift ; json=$1 ; shift ;;
	--job ) shift ; job=$1 ; shift ;;
	--start ) shift ; start=$1 ; shift ;;
	--date ) shift ; date=$1 ; shift ;;
	--directory ) shift ; directory=$1 ; shift ;;
	--commit )
	    shift ; repodir=$1 ; shift ; hash=$1 ; shift
	    details=$(cd ${repodir} && git show --no-patch --format='%s' ${hash})
	    git_date=$(${webdir}/gime-git-date.sh ${repodir} ${hash} \
			   | sed -e 's/T\([0-9]*:[0-9]*\):.*/ \1/')
	    job="${git_date} - ${hash}"
	    ;;
	-* )
	    echo "Unrecognized option: $*" >/dev/stderr
	    exit 1
	    ;;
	* ) details="${details}$1" ; shift ;;
    esac
done

options="job start date details"
for option in ${options} ; do
    if test -z "$(eval echo \$${option})" ; then
	echo "<${option}> missing" > /dev/stderr
	exit 1
    fi
done


echo {} | \
    jq --arg job "${job}" \
       --arg start "${start}" \
       --arg date "${date}" \
       --arg details "${details}" \
       --arg hash "${hash}" \
       --arg directory "${directory}" \
       '
{
    job: $job,
    start: $start,
    date: $date,
    details: $details,
    hash: $hash,
    directory: $directory,
 }' | \
    if test -n "${json}" ; then
	cat > ${json}.tmp
	mv ${json}.tmp ${json}
    else
	cat
    fi
