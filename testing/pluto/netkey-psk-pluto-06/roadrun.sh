ipsec whack --debug-all
ipsec auto --up road--eastnet-psk
ping -n -c 2 192.0.2.254
ipsec auto --status
#ipsec look
ip xfrm policy
ip xfrm state
echo done.

