#!/bin/sh

checkout=true
baseline=
while test $# -gt 0; do
    case $1 in
	--no-checkout ) checkout=false ; shift ;;
	--checkout ) checkout=true ; shift ;;
	--baseline ) baseline=$(cd $2 && pwd) ; shift ; shift ;;
	--*) echo Unknown option $1 1>&2 ; exit 1 ;;
	* ) break ;;
    esac
done

if test "$#" -lt 2; then
    cat <<EOF > /dev/stderr

Usage:

   $0 [ --no-checkout ] [ --baseline <baseline-dir> ] <repo-dir> <results-dir> ...

Create a results web page under <results-dir>.

Use "kvmrunner.py" to create <results-dir>/results.json by comparing
the test output in <results-dir>/*/OUTPUT against the expected output
in <repo-dir>/testing/pluto/*/ and, if multiple <results-dir>
parameters, the previous test output as an additional baseline.

--baseline <baseline-dir>: use <baseline-dir> as the baseline for the
first <results-dir>.

--no-checkout: do not switch <repo-dir> to the checkout used when
creating the test results.

EOF
    exit 1
fi

set -euxv

repodir=$(cd $1 && pwd) ; shift

cwd=$(pwd)
webdir=$(cd $(dirname $0) && pwd)

for d in "$@" ; do
    destdir=$(cd ${d} && pwd)
    gitrev=$(${webdir}/gime-git-rev.sh $(basename ${destdir}))
    if ${checkout} ; then
	(
	    cd ${repodir}
	    git checkout ${gitrev}
	)
    fi
    (
	cd ${destdir}

	${webdir}/results.sh \
		 $(test -n "${baseline}" && echo --baseline "${baseline}") \
		 --testing-directory ${repodir}/testing \
		 . > results.tmp
	jq -s '.' results.tmp > results.new
	rm results.tmp

	cp ${webdir}/i3.html ${destdir}/index.html
	rm -rf ${destdir}/js
	cp -r ${destdir}/../../js ${destdir}/js
	cp ${webdir}/*.js ${destdir}/js

	mv results.new results.json
    )
    baseline=${destdir}
done
