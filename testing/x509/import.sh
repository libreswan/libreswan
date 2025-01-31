#!/bin/sh

# this assumes nss-pki.sh

cd $(dirname $0)

if ! test -r nss-pw ; then
    echo "missing password file: nss-pw" 1>&2
    exit 1
fi

run()
{
    echo "$@"
    "$@"
}

import_root_p12()
{
    ca=$(basename $(dirname $1))
    run ipsec pk12util -w nss-pw -i $1
    run ipsec certutil -M -n "${ca}" -t CT,,
}

import_root_cert()
{
    ca=$(basename $(dirname $1))
    run ipsec certutil -A -n "${ca}" -t CT,, -i $1
}

import_end_p12()
{
    n=$(basename $1 .all.p12)
    ca=$(basename $(dirname $1))
    run ipsec pk12util -w nss-pw -i $1
}

import_all_p12()
{
    n=$(basename $1 .all.p12)
    ca=$(basename $(dirname $1))
    run ipsec pk12util -w nss-pw -i $1
    run ipsec certutil -M -n "${ca}" -t CT,,
}

import_end_cert()
{
    n=$(basename $1 .end.cert)
    run ipsec certutil -A -n "${n}" -t ,, -i $1
}

import_all_cert()
{
    n=$(basename $1 .all.cert)
    ca=$(basename $(dirname $1))
    run ipsec certutil -A -n "${n}" -t ,, -i $1
    run ipsec certutil -M -n "${ca}" -t CT,,
}

for file in "$@" ; do
    if test ! -r ${file} ; then
	echo "missing file: ${file}" 1>&2
	exit 1
    fi
    case ${file} in
	*/root.p12 ) import_root_p12 ${file} ;;
	*/root.cert ) import_root_cert ${file} ;;
	*.all.p12 ) import_all_p12 ${file} ;;
	*.end.p12 ) import_end_p12 ${file} ;;
	*.all.cert ) import_all_cert ${file} ;;
	*.end.cert ) import_end_cert ${file} ;;
	* ) echo "Huh!?! ${file}" 1>&2 ;;
    esac
done
