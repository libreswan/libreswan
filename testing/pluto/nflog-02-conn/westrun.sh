iptables -L -n
ipsec auto --up westnet-eastnet-ikev2
iptables -L -n
rm -fr /tmp/nflog-50.pcap
rm -fr /tmp/nflog-50.log
tcpdump -c 8 -s 0 -w /tmp/nflog-50.pcap -i nflog:50 > /tmp/nflog-50.log 2>&1 &
i=0 ; while test $i -lt 5 && grep -n listening /tmp/nflog-50.log > /dev/null ; do i=$(($i + 1)) ; sleep 1 ; done
ping -n -c 4 -I 192.0.1.254 192.0.2.254 ; wait
cat /tmp/nflog-50.log
ipsec auto --down westnet-eastnet-ikev2
iptables -L -n
cp /tmp/nflog-50.pcap OUTPUT/nflog-50.pcap
cp /tmp/nflog-50.log OUTPUT/nflog-50.log
tcpdump -n -r OUTPUT/nflog-50.pcap
echo done
