/testing/guestbin/swan-prep --userland strongswan
rm -f /etc/strongswan/ipsec.d/cacerts/*
rm -f /etc/strongswan/ipsec.d/certs/*
rm -f /etc/strongswan/ipsec.d/private/*
cp /testing/x509/cacerts/curveca.crt /etc/strongswan/ipsec.d/cacerts/
cp /testing/x509/certs/west-ec.crt /etc/strongswan/ipsec.d/certs/
cp /testing/x509/keys/west-ec.key /etc/strongswan/ipsec.d/private/
chmod 600 /etc/strongswan/ipsec.d/private/*
../../pluto/bin/strongswan-start.sh
echo "initdone"
