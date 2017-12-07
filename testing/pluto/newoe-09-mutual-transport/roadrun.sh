# bring up OE
ping -n -c 4 -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus
# confirm we got transport mode, not tunnel mode
ip xfrm state | grep mode
echo done
