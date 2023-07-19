ipsec auto --up north
sleep  2
../../guestbin/tcpdump.sh --start -i ipsec2
../../guestbin/ping-once.sh --up  192.0.2.254
../../guestbin/ping-once.sh --up  192.0.2.254
../../guestbin/ping-once.sh --up  192.0.2.254
../../guestbin/ping-once.sh --up  192.0.2.254
ip -s link show ipsec2
ip rule show
ip route
ip route show table 50
../../guestbin/tcpdump.sh --stop -i ipsec1
# rm the test specific systemd-networkd file for next test
rm /etc/systemd/network/ipsec2.netdev
echo done
