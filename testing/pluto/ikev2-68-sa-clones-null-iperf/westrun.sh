ipsec auto --status | grep west-east
ipsec auto --up west-east
#taskset 0x1 ping -n -c 2 192.1.2.23
#taskset 0x2 ping -n -c 2 192.1.2.23
ipsec trafficstatus
# base line singe flow
#taskset 0x2 iperf3 -t 45 -i 2 -c 192.1.2.23 -p 5002
cd /var/tmp/
#perf record -g -e cycles --call-graph dwarf & echo "$!"  > $(hostname)-perf.pid
#iperf3 -t 180 -i 2 -c 192.1.2.23 -p 5001 
echo done
