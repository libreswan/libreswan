/testing/guestbin/swan-prep --userland strongswan
ip addr add 192.0.4.254/32 dev eth0
# make sure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.4.0/24 -j LOGDROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
ping -n -c 2 -I 192.0.4.254 192.0.2.254
strongswan starter --debug-all
echo "initdone"
