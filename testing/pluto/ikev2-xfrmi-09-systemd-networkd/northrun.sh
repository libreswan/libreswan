ipsec auto --up north
sleep  2
ping -w 4 -c 4 192.0.2.254
ip -s link show ipsec1
#kill -9 $(cat /tmp/tcpdump.pid)
sleep 2
#cp /tmp/ipsec1.pcap OUTPUT/
ip rule show
ip route show table 50
# copy the old file
cp /testing/baseconfigs/north/etc/systemd/network/eth1.network /etc/systemd/network/eth1.network
# remove extra file north go back to normal after reboot
rm /etc/systemd/network/ipsec1.netdev
echo done
