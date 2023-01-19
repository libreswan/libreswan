/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started

ipsec auto --add 4in4-base
ipsec auto --add 4in4-good
ipsec auto --add 4in4-bad
ipsec auto --add 4in4-protoport

ipsec auto --add 6in6-base
ipsec auto --add 6in6-good
ipsec auto --add 6in6-bad
ipsec auto --add 6in6-protoport

ipsec auto --add 4in6-base # also bad
ipsec auto --add 4in6-good
ipsec auto --add 4in6-bad
ipsec auto --add 4in6-protoport

ipsec auto --add 6in4-base # also bad
ipsec auto --add 6in4-good
ipsec auto --add 6in4-bad
ipsec auto --add 6in4-protoport

ipsec auto --add 44family4
ipsec auto --add 44family6
ipsec auto --add 46family4
ipsec auto --add 46family6
ipsec auto --add 64family4
ipsec auto --add 64family6
ipsec auto --add 66family4
ipsec auto --add 66family6

ipsec status | grep unrouted
