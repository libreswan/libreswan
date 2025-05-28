/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add east-pool
ipsec auto --add east-subnet1
ipsec auto --add east-subnet2
echo initdone
