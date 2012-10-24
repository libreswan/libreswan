
export PLUTO_EVENT_RETRANSMIT_DELAY=3
export PLUTO_MAXIMUM_RETRANSMISSIONS_INITIAL=4

ipsec whack --debug-whackwatch --name westnet-eastnet-ikev2 --initiate  

ipsec look
echo done
