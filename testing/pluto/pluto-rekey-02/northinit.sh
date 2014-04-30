/testing/guestbin/swan-prep
# make sure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.254/32 -j LOGDROP
# confirm with a ping
ping -c 4 -n -I 192.0.3.254 192.0.2.254
ifconfig eth1 192.1.3.32 netmask 255.255.255.0
route add -net default gw 192.1.3.254
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add northnet-eastnet-nat
ipsec auto --status
echo "initdone"
