/testing/guestbin/swan-prep
../../guestbin/ip.sh route get to 192.0.2.254 | grep eth1 && ip route del 192.0.2.0/24 via 192.1.3.254 dev eth1
../../guestbin/ip.sh link show ipsec2 || echo "ipsec2 should not exist"
cp north.ipsec2.netdev  /etc/systemd/network/ipsec2.netdev
: ==== cut ====
# we need this to check systemd creating interface and hard to sanitize
journalctl --rotate
journalctl --vacuum-time=1s
systemctl restart systemd-networkd
# the following output should something like
# Sep 12 05:37:23 systemd[1]: Starting Network Service...
# Sep 12 05:37:23 systemd-networkd[489]: ipsec2: netdev ready
journalctl  --unit=systemd-networkd --no-hostname
: ==== tuc ====
../../guestbin/ip.sh link show ipsec2
echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add north
echo "initdone"
