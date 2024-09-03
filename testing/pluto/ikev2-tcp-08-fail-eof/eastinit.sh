/testing/guestbin/swan-prep --nokeys
dmesg -n 6
# nohup tcpdump -i eth1 -s 65535 -X -vv -nn tcp > OUTPUT/east.tcpdump & sleep 1 # wait for nohup msg
# nohup dumpcap -i eth1 -w /tmp/east.pcap > OUTPUT/east.dumpcap & sleep 1 # wait for nohup msg
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add westnet-eastnet-ikev2
echo "initdone"
