/testing/guestbin/swan-prep
# make sure that clear text does not get through
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
iptables -A INPUT -i eth0 -s 192.0.2.0/24 -j DROP
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add road-eastnet-nonat
ipsec auto --status
echo "initdone"
