#!/bin/sh

set -e
exec 3>&1  # save 3

if test $# -ne 1 ; then
    cat <<EOF 1>&2
Usage: $0 <outdir>
EOF
    exit 1
fi

NOISE_FILE=$0
NOW_VALID_MONTHS=24
NOW_OFFSET_MONTHS=-11

:
: clean up
:

OUTDIR=$1 ; shift
rm -rf ${OUTDIR}/real ${OUTDIR}/fake

PW=${OUTDIR}/nss-pw
if test ! -r ${PW} ; then
    cat <<EOF 1>&2
Missing password file ${PW}
EOF
    exit 1
fi
PASSPHRASE=$(cat ${PW})

:
: Subject DN - NSS wants things local..global
:

SUBJECT="OU=Test Department, O=Libreswan,L=Toronto, ST=Ontario, C=CA"

:
: Generate the basic certificates using NSS
:

echo_2_basic_constraints()
{
    local ca=$1 ; shift
    # -2 - basic constraints
    echo ${ca} # Is this a CA certificate [y/N]?
    echo       # Enter the path length constraint, enter to skip
    echo n     # Is this a critical extension [y/N]?
}

echo_4_crl_constraints()
{
    # -4 - CRL
    echo 1     # Enter the type of the distribution point name: 1 - Full Name
    echo 7     # Select one of the following general name type: 7 - uniformResourceidentifier
    echo http://nic.testing.libreswan.org/revoked.crl  # Enter data:
    echo 0     # Select one of the following general name type: 0 - Any other number to finish
    echo 8     # Select one of the following for the reason flags: 8 - other
    # Enter value for the CRL Issuer name:
    echo 0     # Select one of the following general name type: 0 - Any other number to finish
    echo n     # Enter another value for the CRLDistributionPoint extension [y/N]?
    echo n     # Is this a critical extension [y/N]?
}

echo_extAIA_authority_information_access()
{
    echo 2	# Enter access method type for ...: 2 - OCSP
    echo 7	# Select one of the following general name type: 7 - uniformResourceidentifier
    echo http://nic.testing.libreswan.org:2560
    echo 0	# Select one of the following general name type: 0 - Any other number to finish
    echo n	# Add another location to the Authority Information Access extension [y/N]
    echo n	# Is this a critical extension [y/N]?
}

serial()
{
    local certdir=$1 ; shift
    local serial
    read serial < ${certdir}/serial
    echo $((serial + 1)) > ${certdir}/serial
    echo ${serial}
}

generate_root_cert()
(
    set -x

    local certdir=$1 ; shift
    echo generating root certificate: ${certdir} 1>&3

    local rootname=$(basename ${certdir})

    local ca ; read ca < ${certdir}/root.ca
    local param ; read param < ${certdir}/root.param
    local domain ; read domain < ${certdir}/root.domain

    local serial=$(serial ${certdir})
    echo ${serial} > ${certdir}/root.serial

    # NSS wants subject to be local..global/root
    local subject=${SUBJECT}
    subject="CN=Libreswan test CA for ${rootname}, ${subject}"
    subject="E=testing@libreswan.org, ${subject}"

    # Generate a file containing the constraints that CERTUTIL expects
    # on stdin.
    local cfg=${certdir}/root.cfg
    {
	echo_2_basic_constraints ${ca}
	echo_4_crl_constraints
	echo_extAIA_authority_information_access
    } > ${cfg}

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
	     ${param} \
	     -2 \
	     -4 \
	     --extAIA \
	     < ${cfg}

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

    # print the chain

    chain=$(certutil \
		-O \
		-d ${certdir} \
		-n ${rootname}) || exit 1
    printf "\n%s\n\n" "${chain}" | sed -e 's/^/  /' 1>&3
)

east_ipv4=192.1.2.23
east_ipv6=2001:db8:1:2::23

west_ipv4=192.1.2.45
west_ipv6=2001:db8:1:2::45

generate_end_cert()
(
    set -x

    local certdir=$1 ; shift
    local cert=$1 ; shift
    echo generating end certificate: ${certdir} ${cert} 1>&3

    local rootname=$(basename ${certdir})

    local param ; read param < ${certdir}/root.param
    local domain ; read domain < ${certdir}/root.domain

    local serial=$(serial ${certdir})
    echo ${serial} > ${certdir}/${cert}.serial

    local cn=${cert}.${domain}			# common name
    local e=user-${cert}@testing.libreswan.org	# email

    # NSS wants subject to be local..global/root
    local subject="E=${e}, CN=${cn}, ${SUBJECT}"
    local hash_alg=SHA256
    local ca=n

    # build the SAN
    #
    # Note: SAN's EMAIL and DN's E are unexplainably different.
    local san=dns:${cn},email:${cert}@${domain}
    case ${cert} in
	*east ) san="${san},ip:${east_ipv4},ip:${east_ipv6}" ;;
	*west ) san="${san},ip:${west_ipv4},ip:${west_ipv6}" ;;
    esac
    if test "$#" -gt 0 ; then
	san="${san},$@"
    fi

    # Generate a file containing the constraints that CERTUTIL expects
    # on stdin.
    local cfg=${certdir}/${cert}.cfg
    {
	echo_2_basic_constraints ${ca}
	echo_4_crl_constraints
	echo_extAIA_authority_information_access
    } > ${cfg}

    certutil -S \
	     -d ${certdir} \
	     -s "${subject}" \
	     -n "${cert}" \
	     -z ${NOISE_FILE} \
	     -w ${NOW_OFFSET_MONTHS} \
	     -v ${NOW_VALID_MONTHS} \
	     -c "${rootname}" \
	     -t P,, \
	     -m ${serial} \
	     -g 3072 \
	     --extSAN ${san} \
	     ${param} \
	     --keyUsage digitalSignature \
	     --extKeyUsage serverAuth,clientAuth \
	     -2 \
	     -4 \
	     --extAIA \
	     < ${cfg}

    # private key + cert chain

    pk12util \
	-d ${certdir} \
	-n ${cert} \
	-W ${PASSPHRASE} \
	-o ${certdir}/${cert}.all.p12

    # end cert

    certutil \
	-L \
	-d ${certdir} \
	-n ${cert} \
	-a > ${certdir}/${cert}.end.cert # PEM

    # private key (tests expect it unprotected)

    openssl \
	pkcs12 \
	-passin pass:${PASSPHRASE} \
	-noenc \
	-nocerts \
	-in  ${certdir}/${cert}.all.p12 \
	-out ${certdir}/${cert}.end.key

    # private key + end cert

    openssl \
	pkcs12 \
	-export \
	-passout pass:${PASSPHRASE} \
	-in ${certdir}/${cert}.end.cert \
	-inkey ${certdir}/${cert}.end.key \
	-name ${cert} \
	-out ${certdir}/${cert}.end.p12

    # print the chain

    chain=$(certutil \
		-O \
		-d ${certdir} \
		-n ${cert}) || exit 1
    printf "\n%s\n\n" "${chain}" | sed -e 's/^/  /' 1>&3

)

# generate ca directories

while read base domain ca param ; do

    echo creating cert directory: ${base} ${domain} ${ca} ${param} 1>&2

    certdir=${OUTDIR}/${base}
    mkdir -p ${certdir}
    modutil -create -dbdir "${certdir}" < /dev/null

    log=${certdir}/root.log

    echo 1           > ${certdir}/serial	# next

    echo "${param}"  > ${certdir}/root.param
    echo "${domain}" > ${certdir}/root.domain
    echo "${ca}"     > ${certdir}/root.ca

    # BASE DOMAIN CA? PARAM...
done <<EOF
real/mainca    testing.libreswan.org   y  -k rsa -Z SHA256
real/mainec    testing.libreswan.org   y  -k ec  -Z SHA256 -q secp384r1
real/otherca   other.libreswan.org     y  -k rsa -Z SHA256
fake/mainca    testing.libreswan.org   y  -k rsa -Z SHA256
fake/mainec    testing.libreswan.org   y  -k ec  -Z SHA256 -q secp384r1
real/badca     testing.libreswan.org   n  -k rsa -Z SHA256
EOF

# generate root certificates

for rootdir in ${OUTDIR}/real/* ${OUTDIR}/fake/* ; do

    log=${rootdir}/${root}/root.log
    if ! generate_root_cert ${rootdir} > ${log} 2>&1 ; then
	cat ${log}
	exit 1
    fi

done

# generate end certs where needed

while read kinds roots certs san ; do
    for kind in $(eval echo ${kinds}) ; do
	for root in $(eval echo ${roots}) ; do
	    for cert in $(eval echo ${certs}) ; do
		certdir=${OUTDIR}/${kind}/${root}
		log=${certdir}/${cert}.log
		if ! generate_end_cert ${certdir} ${cert} ${san} > ${log} 2>&1 ; then
		    cat ${log}
		    exit 1
		fi
	    done
	done
    done
done <<EOF
{real,fake} {mainca,mainec} {nic,east,west,road,north,rise,set}
real	    mainca          revoked
real        otherca         other{east,west}
real        badca           bad{east,west}
EOF
