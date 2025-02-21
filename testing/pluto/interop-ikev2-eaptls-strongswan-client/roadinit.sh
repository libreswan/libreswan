/testing/guestbin/swan-prep --userland strongswan

cp /testing/x509/real/mainca/`hostname`.end.cert /etc/strongswan/ipsec.d/certs/`hostname`.crt
cp /testing/x509/real/mainca/`hostname`.end.key /etc/strongswan/ipsec.d/private/`hostname`.key
cp /testing/x509/real/mainca/root.cert /etc/strongswan/ipsec.d/cacerts/mainca.crt

../../guestbin/strongswan-start.sh
echo "initdone"
