#!/bin/sh

if test $# -lt 1 ; then
    cat >> /dev/stderr <<EOF

Usage:

    $0 [ --json <json> ] --job <job> --start <start> --date <date> <details> ...

Update the <json> file with the current status.  Multiple <details>
are allowed and are appended.

By default, json is written to stdout.

EOF
    exit 1
fi

details=
json=
while test $# -gt 0; do
    case $1 in
	--json ) shift ; json=$1 ; shift ;;
	--job ) shift ; job=$1 ; shift ;;
	--start ) shift ; start=$1 ; shift ;;
	--date ) shift ; date=$1 ; shift ;;
	-* )
	    echo "Unrecognized option: $*" >/dev/stderr
	    exit 1
	    ;;
	* )
	    if test -n "${details}" ; then
		details="${details} $1"
	    else
		details=$1
	    fi
	    shift
	    ;;
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
       '{ job: $job, start: $start, date: $date, details: $details }' | \
    if test -n "${json}" ; then
	cat > ${json}.tmp
	mv ${json}.tmp ${json}
    else
	cat
    fi
