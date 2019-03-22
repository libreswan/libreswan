ipsec auto --up west
taskset 0x3 ping -w 3 -n -c 2 192.1.2.23
ipsec trafficstatus
ipsec whack --rekey-ipsec --name west-1
sleep 15
ipsec whack --rekey-ipsec --name west-1
ipsec status | grep STATE_
echo done
