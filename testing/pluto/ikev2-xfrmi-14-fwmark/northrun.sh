ipsec auto --up north
../../guestbin/ping-once.sh -I 192.0.3.254 192.0.2.254
ip -s link show ipsec1
#kill -9 $(cat /tmp/tcpdump.pid)
sleep 2
#cp /tmp/ipsec1.pcap OUTPUT/
ip rule show
../../guestbin/ip.sh route show table 50
../../guestbin/ip.sh route show table 1
# expect if_id and output-mark to be different in ip xfrm state output
# output-mark 0x6/0xffffff
# if_id 1
../../guestbin/ipsec-kernel-state.sh
curl 192.0.2.254:8888
echo done
