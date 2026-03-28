/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add east-pool
ipsec add east-subnet1
ipsec add east-subnet2
echo initdone
