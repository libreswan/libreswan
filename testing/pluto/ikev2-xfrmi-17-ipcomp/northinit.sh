/testing/guestbin/swan-prep
# this route from /etc/sysconfig/network-scripts/route-eth1 interfears
ip route get to 192.0.2.254 | grep eth1 && ip route del 192.0.2.0/24 via 192.1.3.254 dev eth1
# ip link show ipsec1 2>/dev/null && ip link del ipsec1
echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add north
echo "initdone"
