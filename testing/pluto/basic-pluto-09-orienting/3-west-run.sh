# should establish
ipsec auto --up test1
ip addr add 172.29.1.3/24 dev test0
ipsec auto --ready
ipsec auto --up test2
ip addr del 172.29.1.3/24 dev test0
# not read issuing --ready
