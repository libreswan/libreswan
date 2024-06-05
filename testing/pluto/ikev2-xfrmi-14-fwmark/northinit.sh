/testing/guestbin/swan-prep
ip link show dev gre1 2>/dev/null > /dev/null && (ip link set down dev gre1 && ip link del gre1)
ip link add dev gre1 type gretap remote 192.1.2.45 local 192.1.3.33 key 123
ip addr add 192.1.7.33/24 dev gre1
ip link set gre1 up
iptables -t mangle -I OUTPUT -p tcp --dport 8888 -j MARK --set-mark 0x0001
ip rule add prio 1 fwmark 0x0601/0xffff table 1
../../guestbin/ip.sh route add 192.1.2.23 via 192.1.7.45 dev gre1 table 1
# this route from /etc/sysconfig/network-scripts/route-eth1 interferes
../../guestbin/ip.sh route get to 192.0.2.254 | grep eth1 && ip route del 192.0.2.0/24 via 192.1.3.254 dev eth1
echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add north
echo "initdone"
