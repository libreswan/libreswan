/testing/guestbin/swan-prep --x509
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add north
ipsec auto --up north
ping -n -c 4 192.0.2.254
echo "initdone"
