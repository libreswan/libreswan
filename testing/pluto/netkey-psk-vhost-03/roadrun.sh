ipsec whack --debug-all
ipsec auto --up road-east-psk
ping -n -c 2 192.1.2.23
ipsec auto --status
#ipsec look
ip xfrm policy
ip xfrm state
echo done.

