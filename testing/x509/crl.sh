#!/bin/sh

set -e
exec 3>&1  # save STDOUT as 3

if test $# -ne 1 ; then
    cat <<EOF 1>&3
Usage: $0 <outdir>
EOF
    exit 1
fi

OUTDIR=$1 ; shift

certdir=${OUTDIR}/real/mainca

run()
{
    echo "$@"
    "$@"
}

#

day=$((60 * 60 * 24))
now=$(date -u +%s)	# seconds since epoch

format='+%Y%m%d%H%M%SZ'
past=$(date    -d @$((now - day * 15 )) ${format})
present=$(date -d @$((now            )) ${format})
future=$(date  -d @$((now + day * 360)) ${format})

# this CRL is out-of-date

crl=${certdir}/crl-is-out-of-date.crl
echo ${crl}
rm -f ${crl}
run crlutil -d ${certdir} -E -n mainca
run crlutil -d ${certdir} -G -o ${crl} -n mainca <<EOF
update=${past}
nextupdate=${present}
addcert `cat ${certdir}/revoked.serial` ${past}
EOF

# this CRL is up-to-date

crl=${certdir}/crl-is-up-to-date.crl
echo ${crl}
rm -f ${crl}
run crlutil -d ${certdir} -D -n mainca
run crlutil -d ${certdir} -G -o ${crl} -n mainca <<EOF
update=${present}
nextupdate=${future}
addcert $(cat ${certdir}/revoked.serial) ${present}
addcert $(cat ${OUTDIR}/certs/west_chain_revoked.serial) ${present}
EOF
