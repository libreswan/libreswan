/testing/guestbin/swan-prep
ip route get to 192.0.2.254 | grep eth1 && ip route del 192.0.2.0/24 via 192.1.3.254 dev eth1
# ip link show ipsec1 2>/dev/null && ip link del ipsec1
# eth1.network is not necessary for later versions of systemd-networkd
cp north.eth1.network /etc/systemd/network/eth1.network
cp north.ipsec1.netdev  /etc/systemd/network/ipsec1.netdev
journalctl --rotate
journalctl --vacuum-time=1s
systemctl restart systemd-networkd
: ==== cut ====
journalctl  --unit=systemd-networkd --no-hostname
: ==== tuc ====
echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add north
echo "initdone"
