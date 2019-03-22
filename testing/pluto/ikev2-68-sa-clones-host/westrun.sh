ipsec auto --status | grep west-east
ipsec auto --up west-east
taskset 0x1 ping -n -c 2 192.1.2.23
taskset 0x2 ping -n -c 2 192.1.2.23
echo done
