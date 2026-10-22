/testing/guestbin/swan-prep --userland strongswan

cp /testing/x509/pki/real/mainec/root.cert /etc/strongswan/ipsec.d/cacerts/mainec.crt
cp /testing/x509/pki/real/mainec/`hostname`.end.cert /etc/strongswan/swanctl/x509/`hostname`.crt
cp /testing/x509/pki/real/mainec/east.key /etc/strongswan/swanctl/ecdsa/east.key

../../guestbin/strongswan-start.sh
echo "initdone"
