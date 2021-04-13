ipsec auto --up north
sleep  2
tcpdump -w /tmp/north-ikev2-xfrmi-09-systemd-networkd-ipsec2.pcap -s 0 -n -i ipsec2 & echo $! > /tmp/north-ikev2-xfrmi-09-systemd-networkd-tcpdump.pid
ping -n -q -w 4 -c 4 192.0.2.254
ip -s link show ipsec2
ip rule show
ip route
ip route show table 50
kill -9 $(cat /tmp/north-ikev2-xfrmi-09-systemd-networkd-tcpdump.pid)
sync
sleep 2
cp /tmp/north-ikev2-xfrmi-09-systemd-networkd-ipsec2.pcap OUTPUT/
# rm the test specific systemd-networkd file for next test
rm /etc/systemd/network/ipsec2.netdev
echo done
