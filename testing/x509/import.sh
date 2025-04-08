#!/bin/sh

if test $# -lt 1 ; then
    echo "usage: $(basename $0) <file-generated-by-generate.sh>" 1>&2
    exit 1
fi

certutil='ipsec certutil'
pk12util='ipsec pk12util'
crlutil='ipsec crlutil'

if test -r /run/pluto/nsspw ; then
    crlutil="${crlutil} -f /run/pluto/nsspw"
    certutil="${certutil} -f /run/pluto/nsspw"
    pk12util="${pk12util} -k /run/pluto/nsspw"
fi

# this assumes generate.sh

cd $(dirname $0)

if ! test -r nss-pw ; then
    echo "missing password file: nss-pw" 1>&2
    exit 1
fi

run()
{
    echo " $@"
    "$@"
}

print_chain()
{
    local cert=$1 ; shift
    set ipsec certutil -O -n ${cert}
    echo " $@"
    "$@" | sed -e '/^$/d'
}

import_root_p12()
{
    ca=$(basename $(dirname $1))
    run ${pk12util} -w nss-pw -i $1
    run ${certutil} -M -n "${ca}" -t CT,,
    print_chain ${ca}
}

import_root_cert()
{
    ca=$(basename $(dirname $1))
    run ${certutil} -A -n "${ca}" -t CT,, -i $1
    print_chain ${ca}
}

import_all_p12()
{
    n=$(basename $1 .all.p12)
    ca=$(basename $(dirname $1))
    run ${pk12util} -w nss-pw -i $1
    run ${certutil} -M -n "${ca}" -t CT,,
    print_chain ${n}
}

import_all_cert()
{
    n=$(basename $1 .all.cert)
    ca=$(basename $(dirname $1))
    run ${certutil} -A -n "${n}" -t P,, -i $1
    run ${certutil} -M -n "${ca}" -t CT,,
    print_chain ${n}
}

import_end_p12()
{
    n=$(basename $1 .end.p12)
    ca=$(basename $(dirname $1))
    run ${pk12util} -w nss-pw -i $1
    print_chain ${n}
}

import_end_cert()
{
    n=$(basename $1 .end.cert)
    run ${certutil} -A -n "${n}" -t P,, -i $1
    print_chain ${n}
}

import_p12()
{
    n=$(basename $1 .p12)
    ca=$(basename $(dirname $1))
    run ${pk12util} -w nss-pw -i $1
    run ${certutil} -M -n "${ca}" -t CT,,
    print_chain ${n}
}

import_crt()
{
    n=$(basename $1 .crt)
    ca=$(basename $(dirname $1))
    run ${certutil} -A -n "${n}" -t P,, -i $1
    run ${certutil} -M -n "${ca}" -t CT,,
    print_chain ${n}
}

import_crl()
{
    run ${crlutil} -I -i ${1}
}

for file in "$@" ; do
    if test ! -r ${file} ; then
	echo "missing file: ${file}" 1>&2
	exit 1
    fi
    case ${file} in
	*/root.p12 )  import_root_p12 ${file} ;;
	*/root.cert ) import_root_cert ${file} ;;
	*.all.p12 )   import_all_p12 ${file} ;;
	*.end.p12 )   import_end_p12 ${file} ;;
	*.all.cert )  import_all_cert ${file} ;;
	*.end.cert )  import_end_cert ${file} ;;
	*.p12 )       import_p12 ${file} ;;
	*.crt )       import_crt ${file} ;;
	*.crl )       import_crl ${file} ;;
	* ) echo "Huh!?! ${file}" 1>&2 ;;
    esac
done
