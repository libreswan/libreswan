/testing/guestbin/swan-prep --userland strongswan
/testing/x509/strongswan-gen.sh

cp /testing/x509/strongswan/strong-MLDSA-44/strongCAcert.pem /etc/strongswan/ipsec.d/cacerts/mldsa-ca.crt
cp /testing/x509/strongswan/strong-MLDSA-44/strongWestCert.pem /etc/strongswan/ipsec.d/certs/west.crt
cp /testing/x509/strongswan/strong-MLDSA-44/strongWestKey.pem /etc/strongswan/ipsec.d/private/west.key
chmod 600 /etc/strongswan/ipsec.d/private/*

../../guestbin/strongswan-start.sh
echo "initdone"
