/testing/guestbin/swan-prep --userland strongswan
cp /testing/x509/keys/east.key /etc/strongswan/ipsec.d/private/
cp /testing/x509/certs/east.crt /etc/strongswan/ipsec.d/certs/
cp /testing/x509/cacerts/mainca.crt /etc/strongswan/ipsec.d/cacerts/
strongswan starter --debug-all
echo "initdone"
