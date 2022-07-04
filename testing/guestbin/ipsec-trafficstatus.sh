#!/bin/sh
set -u

# a wrapper to around 'ipsec trafficstatus' with sanitizer fluctations in byte count

min=0
max=4294967295 # lets go easy use 2^32-1 even hough xfrm INF is 2^64
result=error

usage() {
	if [ $# -lt 2]; then
		cat <<EOF
Usage:

    $0 sanitize the inBytes=84, outBytes=252 to XXX
    $0 [--min <min> --max <max>] min > (inBytes + outBytes)  < max
       Default min=${min} max=${max} bytes
EOF
		exit 1
	fi
}

function err() {
        local exitcode=$1
        shift
        echo "ERROR: $@" >&2
        exit $exitcode
}

verbose=${verbose-''}
if [ "${verbose}" = "yes" ]; then
	set -x
fi

if [ $# -gt 0 ]; then
	OPTIONS=$(getopt  --long min:,max:,help, -- "$@")
	if (( $? != 0 )); then
	    err 4 "Error calling getopt"
	fi
	eval set -- "$OPTIONS"

	while true; do
	    case "$1" in
		--max )
		    max=$2
		    shift
		    ;;
		--min )
		    min=$2
		    shift
		    ;;
		-- ) shift; break ;;

		*)
		    echo "Unrecognized custom option: $1" 1>&2
		    exit 1
		    ;;
	    esac
	done

	shift $((OPTIND - 1))
fi

if [ $# -ne 0 ]; then
    echo "too many parameters: $@"
    exit 1
fi

it="ipsec trafficstatus"

echo ==== cut ====
echo "${it}"
echo ==== tuc ====

# Run the ping command, capturing output and exit code.  To prevent a
# kernel log line that is emitted part way through the ping from being
# 'cut', ping's 'cut' output is only displayed after the ping has
# finished.

output=$(${it} 2>&1)
status=$?
case "${status}" in
    0)
	inB=0
	outB=12
	inB=$(echo ${output} | sed -e 's/\(.*inBytes=\)\([0-9]*\)\(,.*\)/\2/g')
	outB=$(echo ${output} | sed -e 's/\(.*outBytes=\)\([0-9]*\)\(,.*\)/\2/g')
	bytes=$(expr ${inB} + ${outB})
	if [ ${bytes} -gt ${min} ] && [ ${bytes} -le ${max} ]; then
		result=success
	fi
	;;
    1) result=error ;;
    *) result=${status} ;;
esac

echo ==== cut ====
echo "${output}"
echo ==== tuc ====

case "${result}" in
    success )
	echo ${output} | sed -e 's/\(.*inBytes=\)\([0-9]*\)\(, outBytes=\)\([0-9]*\)\(.*\)/\1XXX\3XXX\5/g'
	exit 0
	;;
    error )
	echo ${result} UNEXPECTED
	echo "# ${it}"
	echo "${output}"
	exit 1
	;;
    * )
        echo unexpected status ${status}
	echo "# ${ping}"
	echo "${output}"
	exit 1 ;;
esac
