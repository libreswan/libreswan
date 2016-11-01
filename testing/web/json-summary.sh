#!/bin/sh

set -eu

if test $# -lt 1 ; then
    cat >> /dev/stderr <<EOF

Usage:

  $0 <results.json> ...

EOF
    exit 1
fi

webdir=$(cd $(dirname $0) && pwd)

for d in "$@"; do
    echo ${d} >> /dev/stderr
    jq --arg directory "$(basename $(dirname $(realpath ${d})))" \
       '
def jtime:  sub(" ";"T") | sub("\\..*";"Z") | fromdate ;

{
  total: (. | length),
  results: (.[] |= .),
  directory: $directory,
}
| .[.results[].result] += 1
| .start_time = ([.results[].start_time | values] | min)
| .end_time = ([.results[].start_time, .results[].end_time] | values | max)
| .runtime = ((.end_time | jtime) - (.start_time | jtime) | strftime("%H:%M"))
| del(.results)' \
       ${d}
done
