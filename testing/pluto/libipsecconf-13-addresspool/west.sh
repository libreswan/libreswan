/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started

ipsec auto --add 4Xin4
ipsec auto --add 4Xin6
ipsec auto --add 6Xin4
ipsec auto --add 6Xin6
