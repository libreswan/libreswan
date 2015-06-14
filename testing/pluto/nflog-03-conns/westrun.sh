iptables -L -n
ipsec auto --up westnet-eastnet-nflog
iptables -L -n
ipsec auto --up west-east-nflog
iptables -L -n
rm -fr /tmp/nflog-50.pcap
tcpdump -c 8 -s 0 -w /tmp/nflog-50.pcap -i nflog:50 &
ping -n -c 2 -I 192.1.2.45 192.1.2.23
ping -n -c 2 -I 192.0.1.254 192.0.2.254
ping -n -c 2 -I 192.1.2.45 192.1.2.23
ping -n -c 2 -I 192.0.1.254 192.0.2.254
ipsec auto --down westnet-eastnet-nflog
iptables -L -n
ipsec auto --down west-east-nflog
iptables -L -n
cp  /tmp/nflog-50.pcap OUTPUT/nflog-50.pcap
tcpdump -n -r OUTPUT/nflog-50.pcap
echo done
