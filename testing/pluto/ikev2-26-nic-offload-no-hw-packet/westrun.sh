# expected to fail
ipsec auto --up west-east-transport
# should be no kernel state leftover
ip xfrm state
ip xfrm policy
echo done
