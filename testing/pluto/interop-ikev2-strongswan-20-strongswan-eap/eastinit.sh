/testing/guestbin/swan-prep --userland strongswan

cp /testing/x509/real/mainca/root.cert /etc/strongswan/ipsec.d/cacerts/
cp /testing/x509/real/mainca/`hostname`.end.key /etc/strongswan/ipsec.d/private/`hostname`.key
cp /testing/x509/real/mainca/east.end.cert /etc/strongswan/ipsec.d/certs/east.crt

../../guestbin/strongswan-start.sh
echo "initdone"
