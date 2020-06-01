taskset 0x2 ping -W 4 -w 1 -n -c 4 192.1.2.23
sleep 4
taskset 0x2 ping -W 4 -w 1 -n -c 4 192.1.2.23
ipsec trafficstatus
taskset 0x1 ping -W 4 -w 1 -n -c 4 192.1.2.23
sleep 4
taskset 0x1 ping -W 4 -w 1 -n -c 4 192.1.2.23
ipsec trafficstatus
echo done
