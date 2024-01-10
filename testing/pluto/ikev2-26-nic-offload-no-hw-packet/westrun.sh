# expected to fail
ipsec auto --up westnet-eastnet-ipv4-psk-ikev2
# should be no kernel state leftover
ip xfrm state
ip xfrm policy
echo done
