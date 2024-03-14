/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started

ipsec status | grep ocsp

ipsec stop

ipsec pluto --ocsp-cache-min-age=100  --ocsp-cache-max-age=1000
ipsec status | grep ocsp

