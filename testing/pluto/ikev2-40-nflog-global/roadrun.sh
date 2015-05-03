ipsec auto --up road-eastnet-nonat
sleep 10
rm -fr /tmp/nflog-50.pcap
tcpdump -s 0 -w /tmp/nflog-50.pcap -i nflog:50 &
ping -n -c 4 192.0.2.254
ipsec eroute
echo done
