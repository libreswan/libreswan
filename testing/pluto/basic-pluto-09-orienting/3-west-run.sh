# should establish
ipsec up test1 # sanitize-retransmits
../../guestbin/ip.sh address add 172.29.1.3/24 dev test0
ipsec listen
ipsec up test2
../../guestbin/ip.sh address del 172.29.1.3/24 dev test0
# not read issuing --ready
