ipsec auto --status | grep west-east
ipsec auto --up west-east
taskset 0x1 ping -n -c 2 192.1.2.23
taskset 0x2 ping -n -c 2 192.1.2.23
ipsec trafficstatus
# base line singe flow
taskset 0x1 iperf3 -i 2 -c 192.1.2.23 -p 5002
#start two flows on different cpus
taskset 0x1 iperf3 -i 5 -c 192.1.2.23 -p 5002 &
taskset 0x2 iperf3 -i 5 -c 192.1.2.23 -p 5003
ipsec trafficstatus
# now the traffic should go through the HEAD SA
taskset 0x3 iperf3 -i 2 -c 192.1.2.23 -p 5004
echo done
