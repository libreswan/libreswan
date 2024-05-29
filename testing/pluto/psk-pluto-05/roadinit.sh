/testing/guestbin/swan-prep
ifconfig eth0 inet 192.1.3.174
../../guestbin/route.sh add default via 192.1.3.254
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add road-east-psk
echo "initdone"
