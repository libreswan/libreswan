#!/bin/sh

set -ex

if test $# -ne 1 ; then
    cat <<EOF 1>&2
Usage: $0 <outdir>
EOF
    exit 1
fi

NOISE_FILE=$0
NOW_VALID_MONTHS=24
NOW_OFFSET_MONTHS=-11
PASSPHRASE=foobar

:
: clean up
:

OUTDIR=$(realpath $1)
mkdir -p ${OUTDIR}

KINDS="real fake"

for kind in ${KINDS} ; do
    rm -rf ${OUTDIR}/${kind}/
done

:
: Generate the basic certificates using NSS
:

SUBJECT='C=CA, ST=Ontario, L=Toronto, O=Libreswan, OU=Test Department'

echo_2_basic_constraints()
{
    local ca=$1 ; shift
    # -2 - basic constraints
    echo ${ca} # Is this a CA certificate [y/N]?
    echo       # Enter the path length constraint, enter to skip
    echo       # Is this a critical extension [y/N]?
}

echo_4_crl_constraints()
{
    # -4 - CRL
    echo 1     # Enter the type of the distribution point name: 1 - Full Name
    echo 7     # Select one of the following general name type: 7 - uniformResourceidentifier
    echo http://nic.testing.libreswan.org/revoked.crl  # Enter data:
    echo 0     # Select one of the following general name type: 0 - Any other number to finish
    echo 0     # Select one of the following for the reason flags: 0 - unused
    echo       # Enter value for the CRL Issuer name:
    echo 0     # Select one of the following general name type: 0 - Any other number to finish
    echo n     # Enter another value for the CRLDistributionPoint extension [y/N]?
    echo n     # Is this a critical extension [y/N]?
}

generate_root_cert()
{
    local certdir=$1 ; shift
    local rootname=$1 ; shift
    local serial=$1 ; shift
    local ca=$1 ; shift
    local key=$1 ; shift

    local subject=${SUBJECT}
    subject="${subject}, CN=Libreswan test CA for ${rootname}"
    subject="${subject}, E=testing@libreswan.org"

    # Generate a file containing the constraints that CERTUTIL expects
    # on stdin.
    local cfg=${certdir}/${rootname}.cfg
    {
	echo_2_basic_constraints ${ca}
	echo_4_crl_constraints
    } > ${cfg}

    local crl_distribution_point_type=1 # full name
    local crl_general_name_type=7 # URI
    local crl_distribution_point=http://nic.testing.libreswan.org/revoked.crl

    certutil -S -d ${certdir} \
	     -m ${serial} \
	     -x \
	     -n "${rootname}" \
	     -s "${subject}" \
	     -w ${NOW_OFFSET_MONTHS} \
	     -v ${NOW_VALID_MONTHS} \
	     --keyUsage digitalSignature,certSigning,crlSigning \
	     --extKeyUsage serverAuth,clientAuth,codeSigning,ocspResponder \
	     -t "CT,C,C" \
	     -z ${NOISE_FILE} \
	     -k ${key} "$@" \
	     -2 -4 < ${cfg}

    # root key + cert

    pk12util \
	-d ${certdir} \
	-n ${rootname} \
	-W ${PASSPHRASE} \
	-o ${certdir}/root.p12

    # root cert

    certutil \
	-L \
	-d ${certdir} \
	-n ${rootname} \
	-a > ${certdir}/root.cert # PEM

}

generate_host_cert()
{
    local certdir=$1 ; shift
    local rootname=$1 ; shift
    local nickname=$1 ; shift
    local serial=$1 ; shift
    local key=$1 ; shift

    local subject=${SUBJECT}
    subject="${subject}, CN=${nickname}.testing.libreswan.org"
    subject="${subject}, E=user-${nickname}@testing.libreswan.org"

    local hash_alg=SHA256
    local ca=n

    # Generate a file containing the constraints that CERTUTIL expects
    # on stdin.
    local cfg=${certdir}/${nickname}.cfg
    {
	echo_2_basic_constraints ${ca}
	echo_4_crl_constraints
    } > ${cfg}

    certutil -S -d ${certdir} \
	     -s "${subject}" \
	     -n "${host}" \
	     -z ${NOISE_FILE} \
	     -c "${rootname}" \
	     -t ",,," \
	     -m ${serial} \
	     -k ${key} "$@" \
	     --keyUsage nonRepudiation,digitalSignature,keyEncipherment \
	     --extKeyUsage serverAuth \
	     -2 -4 < ${cfg}

    # private key + cert chain

    pk12util \
	-d ${certdir} \
	-n ${host} \
	-W ${PASSPHRASE} \
	-o ${certdir}/${host}.all.p12

    # end cert

    certutil \
	-L \
	-d ${certdir} \
	-n ${host} \
	-a > ${certdir}/${host}.end.cert # PEM

    # private key

    openssl \
	pkcs12 \
	-passin pass:${PASSPHRASE} \
	-passout pass:${PASSPHRASE} \
	-password pass:${PASSPHRASE} \
	-nocerts \
	-in  ${certdir}/${host}.all.p12 \
	-out ${certdir}/${host}.end.key

    # private key + end cert

    openssl \
	pkcs12 \
	-export \
	-passin pass:${PASSPHRASE} \
	-password pass:${PASSPHRASE} \
	-in ${certdir}/${host}.end.cert \
	-inkey ${certdir}/${host}.end.key \
	-name ${host} \
	-out ${certdir}/${host}.end.p12

}


# generate root certificates

for kind in ${KINDS} ; do

    while read rootname ca key param ; do

	certdir=${OUTDIR}/${kind}/${rootname}
	mkdir -p ${certdir}
	modutil -create -dbdir "${certdir}" < /dev/null

	serial=1 # from above
	log=${certdir}/${rootname}.log

	if ! generate_root_cert ${certdir} ${rootname} ${serial} ${ca} ${key} ${param} > ${log} 2>&1 ; then
	    cat ${log}
	    exit 1
	fi

	for host in nic east west road north rise set ; do
	    serial=$((serial + 1))
	    log=${certdir}/${host}.log

	    if ! generate_host_cert ${certdir} ${rootname} ${host} ${serial} ${key} ${param} > ${log} 2>&1 ; then
		cat ${log}
		exit 1
	    fi

	done

	# BASE CA? KEY PARAM...
    done <<EOF
mainca    y  rsa -Z SHA256
mainec    y  ec  -Z SHA256 -q secp384r1
EOF

# badca     n  rsa -Z SHA256
# otherca   y  rsa -Z SHA256

done
