/testing/guestbin/swan-prep --userland strongswan
/testing/x509/strongswan-gen.sh

cp /testing/x509/strongswan/strong-MLDSA-44/strongCAcert.pem /etc/strongswan/ipsec.d/cacerts/mldsa-ca.crt
cp /testing/x509/strongswan/strong-MLDSA-44/strongEastCert.pem /etc/strongswan/ipsec.d/certs/east.crt
cp /testing/x509/strongswan/strong-MLDSA-44/strongEastKey.pem /etc/strongswan/ipsec.d/private/east.key
chmod 600 /etc/strongswan/ipsec.d/private/*

../../guestbin/strongswan-start.sh
echo "initdone"
