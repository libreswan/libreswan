ipsec auto --up north
# comments below are to understand/explore the basics : what is going on
# ip link add ipsec1 type xfrm if_id 1 dev eth0
# ip link set ipsec1 up
# ../../guestbin/route.sh add 192.0.2.0/24 dev ipsec1 src 192.0.3.254
# tcpdump -s 0 -n -w /tmp/ipsec1.pcap -i ipsec1 & echo $! > /tmp/tcpdump.pid
sleep  2
../../guestbin/ping-once.sh --up 192.0.2.254
ip -s link show ipsec1
#kill -9 $(cat /tmp/tcpdump.pid)
sleep 2
#cp /tmp/ipsec1.pcap OUTPUT/
ip rule show
../../guestbin/route.sh show table 50
echo done
