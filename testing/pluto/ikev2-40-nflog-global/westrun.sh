# show nflog global ipsec-all rules
iptables -L -n
ipsec auto --up westnet-eastnet-ikev2
rm -fr /tmp/nflog-50.pcap
tcpdump -c 8 -s 0 -w /tmp/nflog-50.pcap -i nflog:50 &
ping -n -c 5 -I 192.0.1.254 192.0.2.254
cp  /tmp/nflog-50.pcap OUTPUT/nflog-50.pcap
tcpdump -n -r OUTPUT/nflog-50.pcap
echo done
