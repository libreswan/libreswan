/testing/guestbin/swan-prep
ipsec setup start
ip addr add 192.0.4.254/32 dev eth0
# make sure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.4.0/24 -j LOGDROP
ping -n -c 2 -I 192.0.4.254 192.0.2.254
echo "initdone"
