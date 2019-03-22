ipsec auto --status | grep westnet-eastnet
ipsec auto --up westnet-eastnet
taskset 0x1 ping -n -c 2 -I 192.0.1.254 192.0.2.254
taskset 0x2 ping -n -c 2 -I 192.0.1.254 192.0.2.254
echo done
