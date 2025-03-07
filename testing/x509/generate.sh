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
    local ca
    local critical
    case $1 in
	+y )   ca=y ; critical=y ;;
	-y|y ) ca=y ; critical=n ;;
	+n )   ca=n ; critical=y ;;
	-n|n ) ca=n ; critical=n ;;
    esac
    # -2 - basic constraints
    echo ${ca}        # Is this a CA certificate [y/N]?
    echo              # Enter the path length constraint, enter to skip
    echo ${critical}  # Is this a critical extension [y/N]?
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

echo_extAIA_ocsp()
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

generate_root_ca()
(
    set -x

    local certdir=$1 ; shift
    local is_ca=$1 ; shift
    local eku=$1 ; shift
    echo generating root certificate: ${certdir} 1>&3

    local root=$(basename ${certdir})

    local param ; read param < ${certdir}/param
    local domain ; read domain < ${certdir}/domain

    local serial=$(serial ${certdir})
    echo ${serial} > ${certdir}/root.serial

    # NSS wants subject to be local..global/root
    local subject=${SUBJECT}
    subject="CN=Libreswan test CA for ${root}, ${subject}"
    subject="E=testing@libreswan.org, ${subject}"

    # Generate a file containing the constraints that CERTUTIL expects
    # on stdin.
    local cfg=${certdir}/root.cfg
    {
	echo_2_basic_constraints ${is_ca}
	echo_4_crl_constraints
	echo_extAIA_ocsp
    } > ${cfg}

    ku=digitalSignature,certSigning,crlSigning

    certutil -S -d ${certdir} \
	     -m ${serial} \
	     -x \
	     -n "${root}" \
	     -s "${subject}" \
	     -w ${NOW_OFFSET_MONTHS} \
	     -v ${NOW_VALID_MONTHS} \
	     --keyUsage ${ku} \
	     $(test ${eku} != - && echo --extKeyUsage ${eku}) \
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
	-n ${root} \
	-W ${PASSPHRASE} \
	-o ${certdir}/root.p12

    # root cert

    certutil \
	-L \
	-d ${certdir} \
	-n ${root} \
	-a > ${certdir}/root.cert # PEM

    # print the chain

    chain=$(certutil \
		-O \
		-d ${certdir} \
		-n ${root}) || exit 1
    printf "\n%s\n\n" "${chain}" | sed -e 's/^/  /' 1>&3
)

east_ipv4=192.1.2.23
east_ipv6=2001:db8:1:2::23

west_ipv4=192.1.2.45
west_ipv6=2001:db8:1:2::45

semiroad_ipv4=192.1.3.209
semiroad_ipv6=2001:db8:1:3::209

generate_cert()
(
    set -x

    echo "generating certificate: $@" 1>&3

    local certdir=$1  ; shift ; echo " certdir=${certdir}" 1>&3
    local root=$1     ; shift ; echo " root=${root}" 1>&3
    local cert=$1     ; shift ; echo " cert=${cert}" 1>&3

    local user=$1     ; shift ; echo " user=${user}" 1>&3
    local add_san=$1  ; shift ; echo " add_san=${add_san}" 1>&3   # Subject Alt Name
    local add_ocsp=$1 ; shift ; echo " add_ocsp=${add_ocsp}" 1>&3 # OCSP (in Authority Information Access)
    local add_crl=$1  ; shift ; echo " add_crl=${add_crl}" 1>&3   # Certificate Revocation List
    local bc=$1       ; shift ; echo " bc=${bc}" 1>&3
    local ku=$1       ; shift ; echo " ku=${ku}" 1>&3    # key usage
    local eku=$1      ; shift ; echo " eku=${eku}" 1>&3  # extended key usage

    local param
    if test "$#" -gt 0 ; then
	param="$@"
    else
	read param < ${certdir}/param
    fi
    echo " param=${param}" 1>&3

    local domain
    read domain < ${certdir}/domain
    echo " domain=${domain}" 1>&3

    local serial=$(serial ${certdir})
    echo ${serial} > ${certdir}/${cert}.serial
    echo " serial=${serial}" 1>&3

    local cn=${cert}.${domain}			# common name
    local e=${user}@testing.libreswan.org	# email

    # NSS wants subject to be local..global/root
    local subject="E=${e}, CN=${cn}, ${SUBJECT}"
    local hash_alg=SHA256

    # build the SAN
    #
    # Note: SAN's EMAIL and DN's E are unexplainably different.
    san=
    if test ${add_san} -gt 0 ; then
	local san=dns:${cn},email:${cert}@${domain}
	case ${cert} in
	    *east ) san="${san},ip:${east_ipv4},ip:${east_ipv6}" ;;
	    *west ) san="${san},ip:${west_ipv4},ip:${west_ipv6}" ;;
	    *semiroad) san="${san},ip:${semiroad_ipv4},ip:${semiroad_ipv6}" ;;
	esac
    fi
    echo " san=${san}" 1>&3

    # Generate a file containing the constraints that CERTUTIL expects
    # on stdin.
    local cfg=${certdir}/${cert}.cfg
    {
	test ${bc} != /        && echo_2_basic_constraints ${bc}
	test ${add_crl}  -gt 0 && echo_4_crl_constraints ${add_crl}
	test ${add_ocsp} -gt 0 && echo_extAIA_ocsp ${add_ocsp}
    } > ${cfg}

    if test ${root} = ${cert} ; then
	trust=CT,C,C
    else
	trust=P,,
    fi
    echo " trust=${trust}"

    certutil -S \
	     -d ${certdir} \
	     -n ${cert} \
	     $(test ${root} = ${cert} && echo -x || echo -c ${root}) \
	     -m ${serial} \
	     -s "${subject}" \
	     -z ${NOISE_FILE} \
	     -w ${NOW_OFFSET_MONTHS} \
	     -v ${NOW_VALID_MONTHS} \
	     -t ${trust} \
	     $(test ${add_san} -gt 0 && echo --extSAN ${san}) \
	     $(test ${ku}  != / && echo --keyUsage ${ku}) \
	     $(test ${eku} != / && echo --extKeyUsage ${eku}) \
	     $(test ${bc}  != / && echo -2) \
	     $(test ${add_crl}  -gt 0 && echo -4) \
	     $(test ${add_ocsp} -gt 0 && echo --extAIA) \
	     ${param} \
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

    openssl pkcs12 \
	-passin pass:${PASSPHRASE} \
	-noenc \
	-nocerts \
	-in  ${certdir}/${cert}.all.p12 \
	-out ${certdir}/${cert}.end.key

    # private key + end cert

    openssl pkcs12 \
	-export \
	-passout pass:${PASSPHRASE} \
	-in ${certdir}/${cert}.end.cert \
	-inkey ${certdir}/${cert}.end.key \
	-name ${cert} \
	-out ${certdir}/${cert}.end.p12

    # dump the cert, log the chain

    certutil \
	-L \
	-d ${certdir} \
	-n ${cert}

    chain=$(certutil \
		-O \
		-d ${certdir} \
		-n ${cert}) || exit 1
    printf "\n%s\n\n" "${chain}" | sed -e 's/^/  /' 1>&3

)

# generate ca directories

while read base domain is_ca param ; do

    case "${base}" in
	'#*' ) continue ;;
    esac

    echo creating cert directory: ${base} ${domain} ${is_ca} ${param} 1>&2

    certdir=${OUTDIR}/${base}
    mkdir -p ${certdir}

    # configure NSS

    modutil -create -dbdir "${certdir}" < /dev/null > /dev/null

    # configure root certificate

    echo 1           > ${certdir}/serial	# next
    echo "${param}"  > ${certdir}/param
    echo "${domain}" > ${certdir}/domain

    # generate root certificate

    eku=serverAuth,clientAuth,codeSigning,ocspResponder

    log=${certdir}/root.log
    if ! generate_root_ca ${certdir} ${is_ca} ${eku} > ${log} 2>&1 ; then
	cat ${log}
	exit 1
    fi

    # BASE DOMAIN IS_CA EKU PARAM...
done <<EOF
real/mainca   testing.libreswan.org  y  -k rsa -Z SHA256 -g 3072
real/mainec   testing.libreswan.org  y  -k ec  -Z SHA256 -q secp384r1
real/otherca  other.libreswan.org    y  -k rsa -Z SHA256 -g 3072
fake/mainca   testing.libreswan.org  y  -k rsa -Z SHA256 -g 3072
fake/mainec   testing.libreswan.org  y  -k ec  -Z SHA256 -q secp384r1
real/badca    testing.libreswan.org  n  -k rsa -Z SHA256 -g 3072
EOF

# generate end certs where needed

while read subdirs roots certs add_san add_ocsp add_crl bc ku eku param ; do

    case "${subdirs}" in
	'#*' ) continue ;;
    esac

    for subdir in $(eval echo ${subdirs}) ; do
	for root in $(eval echo ${roots}) ; do
	    for cert in $(eval echo ${certs}) ; do
		certdir=${OUTDIR}/${subdir}/${root}
		log=${certdir}/${cert}.log
		user=user-${cert}

		if generate_cert \
		     ${certdir} ${root} ${cert} ${user} \
		     ${add_san} ${add_ocsp} ${add_crl} \
		     ${bc} ${ku} ${eku} ${param} \
		     > ${log} 2>&1 ; then
		    :
		else
		    cat ${log}
		    exit 1
		fi

	    done
	done
    done
done <<EOF
{real,fake} {mainca,mainec}  nic                             1 1 1 n digitalSignature  ocspResponder
{real,fake} {mainca,mainec}  {east,west,road,north,rise,set} 1 1 1 n digitalSignature  /
real        mainca           revoked                         1 1 1 n digitalSignature  /
real        mainca           key2032                         1 1 1 n digitalSignature  /  -k rsa -g 2032
real        mainca           key4096                         1 1 1 n digitalSignature  /  -k rsa -g 4096
real        mainca           {east,west}-nosan               0 1 1 n digitalSignature  /
real        mainca           semiroad                        1 1 1 n digitalSignature  /
real        mainca           nic-no-ocsp                     1 0 1 n digitalSignature  /
real        otherca          other{east,west}                1 1 1 n digitalSignature  /
real        badca            bad{east,west}                  1 1 1 n digitalSignature  /
# Key Usage aka KU
real        mainca           west-ku-missing                      1 1 1 n /                             /
real        mainca           west-ku-digitalSignature             1 1 1 n digitalSignature              /
real        mainca           west-ku-nonRepudiation               1 1 1 n nonRepudiation                /
real        mainca           west-ku-digitalSignature-certSigning 1 1 1 n digitalSignature,certSigning  /
real        mainca           west-ku-certSigning                  1 1 1 n certSigning                   /
EOF

while read subdir root cert add_san add_ocsp add_crl bc ku eku param ; do

    case "${subdir}" in
	'#*' ) continue ;;
    esac

    certdir=${OUTDIR}/${subdir}
    log=${certdir}/${cert}.log
    user=${cert}

    if generate_cert \
	   ${certdir} ${root} ${cert} ${user} \
	   ${add_san} ${add_ocsp} ${add_crl} \
	   ${bc} ${ku} ${eku} ${param} \
	   > ${log} 2>&1 ; then
	:
    else
	cat ${log}
	exit 1
    fi
done <<EOF
real/mainca  mainca           east_chain_int_1                1 1 1 y digitalSignature,certSigning,crlSigning  /
real/mainca  east_chain_int_1 east_chain_int_2                1 1 1 y digitalSignature,certSigning,crlSigning  /
real/mainca  east_chain_int_2 east_chain_endcert              1 1 1 n digitalSignature                         /
real/mainca  mainca           west_chain_int_1                1 1 1 y digitalSignature,certSigning,crlSigning  /
real/mainca  west_chain_int_1 west_chain_int_2                1 1 1 y digitalSignature,certSigning,crlSigning  /
real/mainca  west_chain_int_2 west_chain_endcert              1 1 1 n digitalSignature                         /
EOF
