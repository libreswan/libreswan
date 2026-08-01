/testing/guestbin/swan-prep --userland strongswan

cp /testing/x509/pki/real/mainca/`hostname`.end.cert /etc/strongswan/swanctl/x509/`hostname`.crt
cp /testing/x509/pki/real/mainca/`hostname`.key /etc/strongswan/swanctl/rsa/`hostname`.key
cp /testing/x509/pki/real/mainca/root.cert /etc/strongswan/ipsec.d/cacerts/mainca.crt

../../guestbin/strongswan-start.sh
echo "initdone"
