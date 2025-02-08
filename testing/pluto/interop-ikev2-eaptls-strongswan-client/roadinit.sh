/testing/guestbin/swan-prep --userland strongswan
cp /testing/x509/certs/road.crt /etc/strongswan/ipsec.d/certs/
cp /testing/x509/keys/road.key /etc/strongswan/ipsec.d/private/
cp /testing/x509/real/mainca/root.cert /etc/strongswan/ipsec.d/cacerts/
../../guestbin/strongswan-start.sh
echo "initdone"
