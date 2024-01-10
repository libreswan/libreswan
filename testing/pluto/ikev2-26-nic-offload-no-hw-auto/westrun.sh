ipsec auto --up west-east-transport
# should be no crypto hardware options in state
ip xfrm state
ip xfrm policy
echo done
