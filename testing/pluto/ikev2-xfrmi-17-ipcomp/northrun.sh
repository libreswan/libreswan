ipsec auto --up north
# comments below are to understand/explore the basics : what is going on
# ../../guestbin/ip.sh link add ipsec1 type xfrm if_id 1 dev eth0
# ../../guestbin/ip.sh link set ipsec1 up
# ../../guestbin/ip.sh route add 192.0.2.0/24 dev ipsec1 src 192.0.3.254
# tcpdump -s 0 -n -w /tmp/ipsec1.pcap -i ipsec1 & echo $! > /tmp/tcpdump.pid
sleep  2
ip xfrm state
../../guestbin/ping-once.sh --up 192.0.2.254
../../guestbin/ip.sh -s link show ipsec1
#kill -9 $(cat /tmp/tcpdump.pid)
sleep 2
#cp /tmp/ipsec1.pcap OUTPUT/
../../guestbin/ip.sh rule show
../../guestbin/ip.sh route show table 50
# check actual compression
ip -o -s xfrm state|grep "proto comp" | sed "s/^\(.*\)\(lifetime current:.*\)\(add .*$\)/\2/"
../../guestbin/ping-once.sh --up --large 192.0.2.254
ip -o -s xfrm state|grep "proto comp" | sed "s/^\(.*\)\(lifetime current:.*\)\(add .*$\)/\2/"
echo done
