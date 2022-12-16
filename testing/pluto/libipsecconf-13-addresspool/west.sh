/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started

ipsec auto --add comma-4
ipsec auto --add comma-6
ipsec auto --add comma-4-comma
ipsec auto --add comma-6-comma
ipsec auto --add 4-comma
ipsec auto --add 6-comma

ipsec auto --add 4toXin4
ipsec auto --add 4toXin6
ipsec auto --add 6toXin4
ipsec auto --add 6toXin6

ipsec auto --add 4to4in4
ipsec auto --add 4to6in6
ipsec auto --add 6to4in4
ipsec auto --add 6to6in6

ipsec auto --add 46to4in4
ipsec auto --add 64to4in4
ipsec auto --add 46to6in6
ipsec auto --add 64to6in6

ipsec auto --add 46to64in4
ipsec auto --add 64to46in6
