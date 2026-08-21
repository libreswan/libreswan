ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add east-west
ipsec auto --up east-west
# now wait a bit for west to figure out things
sleep 10
