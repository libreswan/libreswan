#!/bin/sh

set -e
exec 3>&1  # save STDOUT as 3

CERTUTIL=${certutil:-${CERTUTIL}}
PK12UTIL=${pk12util:-${PK12UTIL}}
CRLUTIL=${crlutil:-${CRLUTIL}}

if test $# -ne 1 ; then
    cat <<EOF 1>&3
Usage: $0 <outdir>
EOF
    exit 1
fi

DIR=$1
OUTDIR=$1/pki ; shift

certdir=${OUTDIR}/real/mainca

run()
{
    echo "$@"
    "$@"
}

#

day=$((60 * 60 * 24))   # in seconds
now=$(date -u +%s)	# seconds since epoch

format='+%Y%m%d%H%M%SZ'
past=$(date    -d @$((now - day * 15 )) ${format})
present=$(date -d @$((now            )) ${format})
future=$(date  -d @$((now + day * 360)) ${format})

file2c()
{
    {
	hexdump -X $1
    } | {
	echo "static const uint8_t $2[] = {"
	sed -e 's/^[0-9a-f]* */ /' \
	    -e '/^ *$/d' \
	    -e 's/ *$/,/' \
	    -e 's/  /, /g' \
	    -e 's/ / 0x/g'
	echo "};"
    }
}

crls()
{
    crl=$1
    update="$2"
    nextupdate="$3"

    echo ${crl}
    rm -f ${crl}.*
    run ${CRLUTIL} -d ${certdir} -E -n mainca
    run ${CRLUTIL} -d ${certdir} -G -o ${crl}.crl -n mainca <<EOF
update=${update}
nextupdate=${nextupdate}
addcert $(cat ${certdir}/revoked.serial) ${past}
>>>>>>> 6711ec0df3 (testing x509: generate a PKCS#7 wrapped CRL)
EOF
    openssl crl -inform DER -in ${crl}.crl -outform PEM -out ${crl}.pem
    openssl crl2pkcs7 -in ${crl}.pem -outform DER -out ${crl}.p7
    file2c ${crl}.p7 pkcs7 > ${crl}.p7c
}

crls ${certdir}/crl-is-out-of-date "${past}"    "${present}"
crls ${certdir}/crl-is-up-to-date  "${present}" "${future}"
