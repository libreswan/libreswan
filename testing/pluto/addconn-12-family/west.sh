/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started

ipsec add 4in4-base
ipsec add 4in4-good
ipsec add 4in4-bad
ipsec add 4in4-protoport

ipsec add 6in6-base
ipsec add 6in6-good
ipsec add 6in6-bad
ipsec add 6in6-protoport

ipsec add 4in6-base # also bad
ipsec add 4in6-good
ipsec add 4in6-bad
ipsec add 4in6-protoport

ipsec add 6in4-base # also bad
ipsec add 6in4-good
ipsec add 6in4-bad
ipsec add 6in4-protoport

ipsec status | grep '==='
