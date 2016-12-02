#!/bin/sh

set -eu

if test $# -lt 1 ; then
    cat >> /dev/stderr <<EOF

Usage:

  $0 [ --json <file> ] <results.json> ...

Generate a summary of each results.json file.

By default, individual JSON objects are written to stdout.  If <file>
is specified write the JSON objects as a proper list to that file.

EOF
    exit 1
fi

webdir=$(cd $(dirname $0) && pwd)

json=
if test "$1" = "--json" ; then
    shift
    json=$1
    shift
fi

# XXX: there must be a better way to do the .totals.

for d in "$@"; do
    echo ${d} >> /dev/stderr
    directory=$(basename $(dirname $(realpath ${d})))
    branch=$(${webdir}/gime-directory-branch.sh ${directory})
    hash=$(${webdir}/gime-directory-hash.sh ${directory})
    jq --arg directory "${directory}" \
       --arg branch "${branch}" \
       --arg hash "${hash}" \
       '

# convert python time to YYYY-MM-DDTHH:MM:SSZ

def jtime:  sub(" ";"T") | sub("\\..*";"Z") | fromdate ;
.
| (.[] |= .) as $results
| ([.[].start_time | values] | min) as $start_time
| ([.[].start_time | values] + [.[].end_time | values] | max) as $end_time
| {
    directory: $directory,
    branch: $branch,
    hash: $hash,
    total: (. | length),
    # if no tests ran, these are all null
    start_time: $start_time,
    end_time: $end_time,
    runtime: (try (($end_time | jtime) - ($start_time | jtime) | strftime("%H:%M")) catch null),
    totals: (
        reduce .[] as $result (
            {};
            # compute: .[kind][status][result] += 1
            .
            # XXX: .kvmplutotest is a best guess
            [try $result.test_kind catch "kvmplutotest"]
            # XXX: .expected_result is the old name
            [try $result.test_status catch $result.expected_result]
            [$result.result] += 1
        )
    ),
    errors: (
        reduce ([foreach .[]
                  as $result (
                      .;
                      (foreach $result.test_host_names[] as $host (
                          .;
                          $result.errors[$host] | values;
                          .));
                      .)
                 ] | flatten
                 )[]
        as $error (
            {};
            .[$error] += 1
        )
    ),
}
| .[$results[].result] += 1
' ${d}
done | \
    if test -n "${json}" ; then
	jq -s '.' > ${json}.tmp
	mv ${json}.tmp ${json}
    else
	cat
    fi

