ipsec start
../../guestbin/wait-until-pluto-started

ipsec add rise-set
ipsec up rise-set

sleep 10 # give fping some time
