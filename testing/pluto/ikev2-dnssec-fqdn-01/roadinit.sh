/testing/guestbin/swan-prep
# ensure that clear text does not get through
iptables -A INPUT -i eth0 -s 192.0.2.0/24 -j LOGDROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add rad-eastnet-fqdn-ikev2
ipsec auto --status | grep rad-eastnet-fqdn-ikev2
echo "initdone"
