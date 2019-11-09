/testing/guestbin/swan-prep
# ensure that clear text does not get through
iptables -A INPUT -i eth0 -s 192.0.2.0/24 -j LOGDROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add road-eastnet-nonat
ipsec auto --status | grep road-eastnet-nonat
ipsec whack --impair suppress-retransmits
echo "initdone"
