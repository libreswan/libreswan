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
ipsec auto --add 4to4in6
ipsec auto --add 4to6in4
ipsec auto --add 4to6in6
ipsec auto --add 6to4in4
ipsec auto --add 6to4in6
ipsec auto --add 6to6in4
ipsec auto --add 6to6in6

ipsec auto --add 46to4in4
ipsec auto --add 64to4in4
ipsec auto --add 46to6in6
ipsec auto --add 64to6in6

ipsec auto --add 46to64in4
ipsec auto --add 64to46in6

ipsec auto --add good-cat
ipsec auto --add bad-cat

ipsec auto --add good-client
ipsec auto --add bad-client

ipsec auto --add good-server
ipsec auto --add bad-server

ipsec auto --add subnet-vs-addresspool
ipsec auto --add subnets-vs-addresspool

ipsec auto --add narrowing=no-addresspool=yes
ipsec auto --add narrowing=yes-addresspool=yes
