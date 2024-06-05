# should establish
ipsec auto --up test1
../../guestbin/ip.sh address add 172.29.1.3/24 dev test0
ipsec auto --ready
ipsec auto --up test2
../../guestbin/ip.sh address del 172.29.1.3/24 dev test0
# not read issuing --ready
