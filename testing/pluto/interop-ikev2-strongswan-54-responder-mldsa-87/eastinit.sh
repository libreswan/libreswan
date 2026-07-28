/testing/guestbin/swan-prep --userland strongswan
/testing/x509/strongswan-gen.sh

cp /testing/x509/pki/strongswan/strong-MLDSA-87/strongCAcert.pem /etc/strongswan/ipsec.d/cacerts/mldsa-ca.crt
cp /testing/x509/pki/strongswan/strong-MLDSA-87/strongEastCert.pem /etc/strongswan/ipsec.d/certs/east.crt
cp /testing/x509/pki/strongswan/strong-MLDSA-87/strongEastKey.pem /etc/strongswan/ipsec.d/private/east.key
chmod 600 /etc/strongswan/ipsec.d/private/*

../../guestbin/strongswan-start.sh
echo "initdone"
