#!/bin/sh

set -eu

if test $# -lt 3 ; then
    cat <<EOF > /dev/stderr

Usage:

  $0 <repo> <summarydir> <results.json> ...

EOF
    exit 1
fi

repodir=$(cd $1 && pwd) ; shift
summarydir=$(cd $1 && pwd) ; shift
webdir=$(cd $(dirname $0) && pwd)

for d in "$@"; do
    echo ${d} >> /dev/stderr
    rev=$(${webdir}/gime-git-rev.sh $(dirname ${d}))
    date=$(${webdir}/gime-git-date.sh ${repodir} ${rev})
    rank=$(${webdir}/gime-git-rank.sh ${repodir} ${rev})

    baseline=$(${webdir}/gime-git-elder.sh ${repodir} $(dirname ${d}))
    d=$(realpath ${d})
    (
	cd ${summarydir}
	jq \
	    --arg rev "${rev}" \
	    --arg date "${date}" \
	    --argjson rank "${rank}" \
	    '
def jtime:  sub(" ";"T") | sub("\\..*";"Z") | fromdate ;

{
  date: $date,
  revision: $rev,
  rank: $rank,
  total: (. | length),
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
