#!/bin/sh

set -eu

if test $# -lt 3 ; then
    cat <<EOF > /dev/stderr

Usage:

  $0 <repo> <basedir> <results.json> ...

EOF
    exit 1
fi

repodir=$(cd $1 && pwd) ; shift
basedir=$(cd $1 && pwd) ; shift
webdir=$(cd $(dirname $0) && pwd)

for d in "$@"; do
    rev=$(${webdir}/gime-git-rev.sh $(dirname ${d}))
    date=$(${webdir}/gime-git-date.sh ${repodir} ${rev})
    nextrev=$(cd ${repodir} ; git rev-list ${rev}..HEAD | tail -n 2 | head -1)
    if test -n "${nextrev}" ; then
	next=$(${webdir}/gime-git-date.sh ${repodir} ${nextrev})
    else
	next=""
    fi
    d=$(realpath ${d})
    (
	cd ${basedir}
	jq \
	    --arg rev "${rev}" \
	    --arg date "${date}" \
	    --arg next "${next}" \
	    '
def jtime:  sub(" ";"T") | sub("\\..*";"Z") | fromdate ;

{
  date: $date,
  rev: $rev,
  next_date: $next,
  Total: (. | length),
  results: (.[] |= .),
  directory: (input_filename | sub("/[^/]*$";"")),
}
| .[.results[].result] += 1
| .start_time = ([.results[].start_time | values] | min)
| .end_time = ([.results[].start_time, .results[].end_time] | values | max)
| .runtime = ((.end_time | jtime) - (.start_time | jtime) | strftime("%H:%M"))
| del(.results)' \
	    $(realpath --relative-to . ${d})
    )
done
