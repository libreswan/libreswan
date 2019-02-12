# capture IKE to test for fragmentation
tcpdump -i eth1 -n -w /tmp/ike.pcap -s 0 -c 3 port 500 or port 4500 &
# should not fail
ipsec auto --up  westnet-eastnet-ikev2
ping -c 3 -I 192.0.1.254 192.0.2.254
# should not show fragments
tcpdump -n -r /tmp/ike.pcap
echo done
