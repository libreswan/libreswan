ipsec auto --up  westnet-eastnet
# should get blocked by our firewall rule, because it takes high prio passthrough
ping -n -c 4 -I 192.0.1.254 192.0.2.254
echo done
