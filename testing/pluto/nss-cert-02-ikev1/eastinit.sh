/testing/guestbin/swan-prep --x509
ipsec certutil -D -n west
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add nss-cert
ipsec auto --status |grep nss-cert
echo "initdone"
