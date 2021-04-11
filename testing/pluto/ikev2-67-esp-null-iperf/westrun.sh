ipsec auto --status | grep west-east
ipsec auto --up west-east
# taskset 0x1 ping -n -q -c 2 192.1.2.23
ipsec trafficstatus
# base line singe flow
taskset 0x1 iperf3 -t 45 -i 2 -c 192.1.2.23 -p 5001
# cd /var/tmp/
# perf record -g -e cycles --call-graph dwarf & echo "$!"  > OUTPUT/$(hostname)-perf.pid
# iperf3 -t 180 -i 2 -c 192.1.2.23 -p 5001
ipsec status | grep west-east
ipsec auto --down west-east
ipsec auto --delete west-east
ipsec auto --initiate west-east-null
taskset 0x1 iperf3 -t 45 -i 2 -c 192.1.2.23 -p 5001
ipsec status | grep west-east-null
echo done
