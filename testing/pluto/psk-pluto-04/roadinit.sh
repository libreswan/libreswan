/testing/guestbin/swan-prep 
ifconfig eth0 inet 192.1.3.174
route add -net default gw 192.1.3.254
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add road-east-psk
echo "initdone"
