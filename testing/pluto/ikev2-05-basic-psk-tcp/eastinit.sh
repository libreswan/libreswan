/testing/guestbin/swan-prep
#drop all ESP and UDP traffic
iptables -A INPUT -p udp -j DROP
iptables -A OUTPUT -p udp -j DROP
iptables -A INPUT -p esp -j DROP
iptables -A OUTPUT -p esp -j DROP
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ipv4-psk-ikev2
echo "initdone"
