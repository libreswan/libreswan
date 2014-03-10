tcpdump -i lo -n -s 0 -w /tmp/tcpdump-lo.pcap 2> /dev/null &
sleep 1
echo PLAINTEXT | nc 127.0.0.1 22
ping -n -c 1 127.0.0.2
ipsec auto --up wide
ipsec look
echo ENCRYPTED | nc 127.0.0.1 666
echo ENCRYPTED | nc 127.0.0.1 22
ping -n -c 1 127.0.0.3
ipsec auto --route narrow
ipsec look
echo ENCRYPTED | nc 127.0.0.1 666
echo PLAINTEXT | nc 127.0.0.1 22
sleep 1
killall tcpdump
tcpdump -r /tmp/tcpdump-lo.pcap -n src 127.0.0.1 or src 127.0.0.2 or src 127.0.0.3
echo done
