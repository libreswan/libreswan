#!/bin/sh

if test $# -lt 1 ; then
    cat >> /dev/stderr <<EOF

Usage:

    $0 [ --json <json> ] --resultsdir <logdir> <make-target> ....

Update the <json> file with the list of make targets and corresponding
log files (found in <logdir>).  If <json> isn't specified write to
stdout.

EOF
    exit 1
fi

bindir=$(cd $(dirname $0) && pwd)

json=
resultsdir=
targets=
while test $# -gt 0; do
    case $1 in
	--json ) shift ; json=$1 ; shift ;;
	--resultsdir ) shift ; resultsdir=$1 ; shift ;;
	-* ) echo "Unrecognized option: $*" >/dev/stderr ; exit 1 ;;
	* ) targets="${targets}${sp}$1" ; sp=" " ; shift ;;
    esac
done

if test "${resultsdir}" = "" -o ! -d "${resultsdir}" ; then
    echo "no resultsdir: ${resultsdir}" >> /dev/stderr
    exit 1
fi

{
    for t in ${targets} ; do
	if test -r ${resultsdir}/${t}.log || test "${t}" = "${target}"; then
	    # json
	    logfile="\"${t}.log\""
	else
	    # json
	    logfile=null
	fi
	jq --null-input --arg target "${t}" --argjson logfile "${logfile}" \
	   '{ target: $target, logfile: $logfile, }'
    done
} | {
    # convert to an array
    jq -s .
} | {
    if test -n "${json}" ; then
	cat > ${json}.tmp
	mv ${json}.tmp ${json}
    else
	cat
    fi
}
