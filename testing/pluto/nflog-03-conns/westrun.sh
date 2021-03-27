iptables -L -n
ipsec auto --up westnet-eastnet-nflog
iptables -L -n
ipsec auto --up west-east-nflog
iptables -L -n
rm -fr /tmp/nflog-50.pcap
set +m # silence job control
tcpdump -c 4 -s 0 -w /tmp/nflog-50.pcap -i nflog:50 >/dev/null 2>&1 &
../../pluto/bin/ping-once.sh --up -I 192.1.2.45 192.1.2.23
../../pluto/bin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
../../pluto/bin/ping-once.sh --up -I 192.1.2.45 192.1.2.23
../../pluto/bin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
wait
cp  /tmp/nflog-50.pcap OUTPUT/nflog-50.pcap
tcpdump -n -r OUTPUT/nflog-50.pcap 2>/dev/null
ipsec auto --down westnet-eastnet-nflog
iptables -L -n
ipsec auto --down west-east-nflog
iptables -L -n
echo done
