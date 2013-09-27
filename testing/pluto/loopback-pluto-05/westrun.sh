# this is not the best to sanitize :P
/usr/sbin/tcpdump -i lo -s 0 -n -w /tmp/tcpdump-lo.pcap &
sleep 2
echo PLAINTEXT | nc 127.0.0.1 22
ping -c 1 127.0.0.2
ipsec auto --up wide
ip xfrm policy
echo ENCRYPTED | nc 127.0.0.1 666
echo ENCRYPTED | nc 127.0.0.1 22
ping -c 1 127.0.0.2
ipsec auto --route narrow
ip xfrm policy
echo ENCRYPTED | nc 127.0.0.1 666
echo PLAINTEXT | nc 127.0.0.1 22
sleep 1
killall tcpdump
tcpdump -r /tmp/tcpdump-lo.pcap -n src 127.0.0.1 or src 127.0.0.2
echo done
