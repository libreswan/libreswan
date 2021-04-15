#!/bin/sh

if test $# -eq 0 ; then
    cat <<EOF 1>&2
Usage: $0 <test-directory> ...
Renames test scripts adding a number prefix to each.
EOF
fi

for d in "$@" ; do
    n=1
    ./testing/utils/kvmresults.py --print test-scripts ${d} \
	| sed -e 's;,;\n;g' -e 's;:; ;g' \
	| while read h f ; do
	case ${f} in
	    ${h}init.sh )
		git mv -v ${d}/${f} $d/${n}-${h}-init.sh
		;;
	    ${h}run.sh )
		git mv -v ${d}/${f} ${d}/${n}-${h}-run.sh
		;;
	esac
	n=$(expr ${n} + 1)
    done
done
