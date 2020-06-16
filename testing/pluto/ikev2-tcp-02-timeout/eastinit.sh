/testing/guestbin/swan-prep
# dmesg -n 6
# nohup tcpdump -i eth1 -s 65535 -X -vv -nn tcp > OUTPUT/east.tcpdump &
# nohup dumpcap -i eth1 -w /tmp/east.pcap > OUTPUT/east.dumpcap &
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
echo "initdone"
