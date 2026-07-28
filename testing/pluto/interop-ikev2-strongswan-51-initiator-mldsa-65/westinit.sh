/testing/guestbin/swan-prep --userland strongswan

cp /testing/x509/pki/strongswan/strong-MLDSA-65/strongCAcert.pem /etc/strongswan/ipsec.d/cacerts/mldsa-ca.crt
cp /testing/x509/pki/strongswan/strong-MLDSA-65/strongWestCert.pem /etc/strongswan/ipsec.d/certs/west.crt
cp /testing/x509/pki/strongswan/strong-MLDSA-65/strongWestKey.pem /etc/strongswan/ipsec.d/private/west.key
chmod 600 /etc/strongswan/ipsec.d/private/*

../../guestbin/strongswan-start.sh
echo "initdone"
