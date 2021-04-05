# Do not populate NSS DB, check it is empty
/testing/guestbin/swan-prep
certutl -L -d sql:/etc/ipsec.d
# workaround for  https://bugzilla.redhat.com/show_bug.cgi?id=1848649
/u../../guestbin/update-crypto-policies
# setup softhsm with east's PKCS12 info
#SOFTHSM2_CONF="/etc/softhsm2.conf"
#SOFTHSM2_TOKEN_DIR="$(grep 'directories.tokendir' "$SOFTHSM2_CONF" | cut -d '=' -f 2 | sed 's/ //g')"
export GNUTLS_PIN=123456
export GNUTLS_SO_PIN=12345678
export GNUTLS_NEW_SO_PIN=12345678
# delete any old libreswan softhsm token - bug in p11tool that it does not delete everything ?
#OLDSOFTHSM=$(p11tool --list-tokens |grep libreswan |grep URL| sed "s/URL://")
#if [ -n "${OLDSOFTHSM}" ] ; then p11tool --batch --delete "${OLDSOFTHSM}" > /dev/null 2> /dev/null ; fi
rm -rf /var/lib/softhsm/tokens/*
# init new one - must use same CKAID for at least key+cert
softhsm2-util --init-token --slot 0 --label libreswan --so-pin ${GNUTLS_SO_PIN} --pin ${GNUTLS_PIN}
p11tool --provider /usr/lib64/pkcs11/libsofthsm2.so --id 01 --write --load-certificate /testing/x509/certs/east.crt --label eastCert --login
p11tool --provider /usr/lib64/pkcs11/libsofthsm2.so --id 01 --write --load-privkey /testing/x509/keys/east.key --label eastKey --login
# note: --trusted --ca does not seem to set the trust bits needed for CA for nss - so fixup afterwards
p11tool --provider /usr/lib64/pkcs11/libsofthsm2.so --id 01 --write --trusted --ca --load-certificate /testing/x509/cacerts/mainca.crt --label eastCA --so-login
echo -n "123456" > /tmp/pin
certutil -h "pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;token=libreswan" -M -t CT,, -n "libreswan:eastCA" -d sql:/etc/ipsec.d -f /tmp/pin
#p11tool --list-all "pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;token=libreswan" --login
CERT_URI=$(p11tool --list-all "pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;token=libreswan" --login | grep eastCert |grep -v Label | cut -d ':' -f '2-' | sed 's/ //g')
KEY_URI=$(p11tool --list-all "pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;token=libreswan" --login | grep eastKey |grep -v Label | cut -d ':' -f '2-' | sed 's/ //g')
echo "CERT_URI=${CERT_URI}"
echo "KEY_URI=${KEY_URI}"
echo -e "conn eastcert\n\trightcert=${CERT_URI}" > OUTPUT/eastcert.conf
echo -e "NSS Certificate DB:${GNUTLS_PIN}\nNSS FIPS 140-2 Certificate DB:${GNUTLS_PIN}\nlibreswan:${GNUTLS_PIN}" > /etc/ipsec.d/nsspassword 
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
ipsec auto --listall
echo "initdone"
