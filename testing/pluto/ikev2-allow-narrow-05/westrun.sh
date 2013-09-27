ipsec auto --up  westnet-eastnet-ikev2
ipsec look
# test if TCP still flows
echo quit | nc 192.1.2.23 22
# confirm ICMP no longer flows (silly but RFC tickbox item)
ping -c 1 -I 192.1.2.45 192.1.2.23
echo done
