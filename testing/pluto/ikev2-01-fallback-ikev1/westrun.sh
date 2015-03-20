export PLUTO_EVENT_RETRANSMIT_DELAY=2
export PLUTO_MAXIMUM_RETRANSMISSIONS_INITIAL=2
export PLUTO_MAXIMUM_RETRANSMISSIONS=6
ipsec auto --up  westnet-eastnet-ikev2
sleep 5
ping -n -c 2 -I 192.0.1.254 192.0.2.254
ipsec look
echo done
