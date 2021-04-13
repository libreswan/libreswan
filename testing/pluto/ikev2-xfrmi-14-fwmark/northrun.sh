ipsec auto --up north
ping -n -q -w 4 -c 4 -I 192.0.3.254 192.0.2.254
ip -s link show ipsec1
#kill -9 $(cat /tmp/tcpdump.pid)
sleep 2
#cp /tmp/ipsec1.pcap OUTPUT/
ip rule show
ip route show table 50
ip route show table 1
# expect if_id and output-mark to be different in ip xfrm state output
# output-mark 0x6/0xffffff
# if_id 1
ip xfrm state
curl 192.0.2.254:8888
echo done
