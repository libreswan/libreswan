ipsec auto --up westnet-eastnet-ipv4-psk-ikev2
# should be no crypto hardware options in state
ip xfrm state
ip xfrm policy
echo done
