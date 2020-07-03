/testing/guestbin/swan-prep
# dmesg -n 6
# nohup tcpdump -i eth1 -s 65535 -X -vv -nn tcp > OUTPUT/west.tcpdump &
# nohup dumpcap -i eth1 -w /tmp/west.pcap > OUTPUT/west.dumpcap &
# confirm that the network is alive
# ../../pluto/bin/wait-until-alive -I 192.0.1.254 192.0.2.254
# make sure that clear text does not get through
# iptables -F
# iptables -X
# does this block the ping response?
# iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j DROP
# iptables -A OUTPUT -o eth1 -p tcp --dport 4500 -j ACCEPT
# confirm with a ping
# ../../pluto/bin/ping-once.sh --down -I 192.0.1.254 192.0.2.254
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
ipsec auto --status | grep westnet-eastnet-ikev2
echo "initdone"
