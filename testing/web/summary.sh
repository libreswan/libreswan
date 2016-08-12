#!/bin/sh

set -eu

if test $# -lt 2 ; then
    cat <<EOF > /dev/stderr

Usage:

  $0 <repo> <results.json> ...

EOF
    exit 1
fi
repo=$(cd $1 && pwd) ; shift
webdir=$(cd $(dirname $0) && pwd)

for d in "$@"; do
    rev=$(${webdir}/gime-git-rev.sh $(dirname ${d}))
    date=$(${webdir}/gime-git-date.sh ${repo} ${rev})
    jq --arg date "${date}" '
def jtime:  sub(" ";"T") | sub("\\..*";"Z") | fromdate ;

{
  date: $date,
  Total: (. | length),
  results: (.[] |= .),
  directory: (input_filename | sub("/[^/]*$";"")),
}
| .[.results[].result] += 1
| .start_time = ([.results[].start_time | values] | min)
| .end_time = ([.results[].start_time, .results[].end_time] | values | max)
| .runtime = ((.end_time | jtime) - (.start_time | jtime) | strftime("%H:%M"))
| del(.results)' ${d}
done
