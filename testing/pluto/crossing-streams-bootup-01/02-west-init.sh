/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add east-west
# initiate async, wait 10 seconds so we get into the 20s retransmit
# timer, giving us time to quickly start east and initiate from there
ipsec auto --up east-west --asynchronous
sleep 10
