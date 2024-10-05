ipsec start
../../guestbin/wait-until-pluto-started

ipsec add east-west
ipsec up east-west

sleep 10 # give fping some time
