/testing/guestbin/swan-prep --x509
ipsec certutil -D -n east
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add nss-cert
echo "initdone"
ipsec auto --up nss-cert
echo done
