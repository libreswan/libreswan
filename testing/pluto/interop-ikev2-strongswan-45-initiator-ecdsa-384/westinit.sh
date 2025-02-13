/testing/guestbin/swan-prep --userland strongswan

cp /testing/x509/real/mainec/root.cert /etc/strongswan/ipsec.d/cacerts/mainec.crt
cp /testing/x509/real/mainec/`hostname`.end.cert /etc/strongswan/ipsec.d/certs/`hostname`.crt
cp /testing/x509/real/mainec/`hostname`.end.key /etc/strongswan/ipsec.d/private/`hostname`.key
chmod 600 /etc/strongswan/ipsec.d/*/*

../../guestbin/strongswan-start.sh
echo "initdone"
