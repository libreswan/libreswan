/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add xauth-road-to-east-on-road
ipsec auto --add east-to-road-on-road
echo done
