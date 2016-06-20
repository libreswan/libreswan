/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add north-east-port3
nc -4 -l 192.1.2.23 2 &
nc -4 -l 192.1.2.23 3 &
echo "initdone"
