/testing/guestbin/swan-prep --46
ipsec start
../../guestbin/wait-until-pluto-started

ipsec add comma-4
ipsec add comma-6
ipsec add comma-4-comma
ipsec add comma-6-comma
ipsec add 4-comma
ipsec add 6-comma

ipsec add 4toXin4
ipsec add 4toXin6
ipsec add 6toXin4
ipsec add 6toXin6

ipsec add 4to4in4
ipsec add 4to4in6
ipsec add 4to6in4
ipsec add 4to6in6
ipsec add 6to4in4
ipsec add 6to4in6
ipsec add 6to6in4
ipsec add 6to6in6

ipsec add 46to4in4
ipsec add 64to4in4
ipsec add 46to6in6
ipsec add 64to6in6

ipsec add 46to64in4
ipsec add 64to46in6

ipsec add good-cat
ipsec add bad-cat

ipsec add good-client
ipsec add bad-client

ipsec add good-server
ipsec add bad-server

ipsec add subnet-vs-addresspool
ipsec add subnets-vs-addresspool

ipsec add narrowing=no-addresspool=yes
ipsec add narrowing=yes-addresspool=yes

ipsec add ipv4-range-starts-at-zero
ipsec add ipv4-cidr-starts-at-zero

ipsec add ipv6-range-starts-at-zero
ipsec add ipv6-cidr-starts-at-zero

ipsec add ipv4-range-overlap-slash-28
ipsec add ipv4-range-overlap-slash-24
ipsec add ipv6-range-overlap-slash-120
ipsec add ipv6-range-overlap-slash-124

ipsec add ipv6-range-overflow-slash-96
ipsec add ipv6-range-overflow-slash-95
ipsec add ipv6-range-overflow-slash-63
