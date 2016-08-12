#!/bin/sh

checkout=true
while test $# -gt 0; do
    case $1 in
	--no-checkout ) checkout=false ; shift ;;
	--checkout ) checkout=true ; shift ;;
	--*) echo Unknown option $1 1>&2 ; exit 1 ;;
	* ) break ;;
    esac
done

if test "$#" -lt 2; then
    cat <<EOF > /dev/stderr

Usage:

   $0 [ --no-checkout ] <repodir> <results-directory> ...

Using <repodir>, update the web pages in <results-directory> (it
doesn't update the OUTPUT files, but perhaps it should).

Unless --no-checkout, this will checkout the sources (in <repodir>)
that were used to generate <results-directory>.

Unless --no-checkout is specified, do not run this from the current
repo.

EOF
    exit 1
fi

set -euxv

repodir=$(cd $1 && pwd) ; shift

cwd=$(pwd)
webdir=$(cd $(dirname $0) && pwd)

for d in "$@" ; do
    destdir=$(cd ${d} && pwd)
    gitrev=$(${webdir}/gime-git-rev.sh $(basename ${d}))
    if ${checkout} ; then
	(
	    cd ${repodir}
	    git checkout ${gitrev}
	)
    fi
    (
	cd ${destdir}

	${webdir}/results.sh \
		 --testing-dir ${repodir}/testing \
		 . > results.tmp
	jq -s '.' results.tmp > results.new
	rm results.tmp

	cp ${webdir}/i3.html ${destdir}/index.html
	rm -rf ${destdir}/js
	cp -r ${destdir}/../../js ${destdir}/js
	cp ${webdir}/*.js ${destdir}/js

	mv results.new results.json
    )
done
