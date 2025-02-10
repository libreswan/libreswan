/testing/guestbin/swan-prep --userland strongswan

cp /testing/x509/real/mainca/root.cert /etc/strongswan/ipsec.d/cacerts/mainca.crt
cp /testing/x509/keys/`hostname`.key /etc/strongswan/ipsec.d/private/
cp /testing/x509/certs/`hostname`.crt /etc/strongswan/ipsec.d/certs/

../../guestbin/strongswan-start.sh
echo "initdone"
