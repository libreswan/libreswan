/testing/guestbin/swan-prep
# make sure that clear text does not get through
iptables -A INPUT -i eth0 -s 192.0.2.0/24 -j DROP
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add road-eastnet-nonat
ipsec auto --status
echo "initdone"
