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

   $0 [ --no-checkout ] <repodir> <basedir> ...

Using <repodir>, update the web pages in <basedir>.

EOF
    exit 1
fi

set -euxv

repodir=$(cd $1 && pwd) ; shift
basedir=$(cd $1 && pwd) ; shift

webdir=$(cd $(dirname $0) && pwd)

cd ${basedir}

${webdir}/summary.sh ${repodir} */*/results.json > summary.tmp
jq -s '.' summary.tmp > summary.new
rm summary.tmp

cp ${webdir}/i1.html index.html
cp ${webdir}/*.js js/

mv summary.new summary.json
