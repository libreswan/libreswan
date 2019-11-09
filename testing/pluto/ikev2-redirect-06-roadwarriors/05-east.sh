sleep 2
# both clients should be connected now
ipsec whack --trafficstatus
# send REDIRECT in informational to north
ipsec whack --redirect --peer-ip 192.1.3.33 --gateway 192.1.2.45
# give north time to be redirected
sleep 2
# only road should be left connected to east. north has gone to west
