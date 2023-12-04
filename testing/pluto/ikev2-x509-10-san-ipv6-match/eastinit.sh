/testing/guestbin/swan-prep --x509 --46
ipsec certutil -D -n west
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add san
echo "initdone"
