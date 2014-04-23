/testing/guestbin/swan-prep
# confirm that the network is alive
ping -n -c 4 -I 192.1.2.45 192.1.2.23
# make sure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.1.2.23/32 -p icmp -j LOGDROP
# confirm with a ping
ping -n -c 4 -I 192.1.2.45 192.1.2.23
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add ipv4-psk-ikev2-transport
ipsec auto --status
echo "initdone"
