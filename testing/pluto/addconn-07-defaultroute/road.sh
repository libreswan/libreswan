/testing/guestbin/swan-prep --46

../../guestbin/route.sh -4
../../guestbin/route.sh -6

# %any
../../guestbin/route.sh -4 get to 0.0.0.0
../../guestbin/route.sh -6 get to ::

# gateway
../../guestbin/route.sh -4 get to 192.1.3.254
../../guestbin/route.sh -6 get to 2001:db8:1:3::254

# peer
../../guestbin/route.sh -4 get to 192.1.2.23
../../guestbin/route.sh -6 get to 2001:db8:1:2::23

# simple case, peer known

ipsec addconn --verbose ipv4-src 2>&1 | grep -e '^resolving ' -e '^  [^ ]'
ipsec addconn --verbose ipv6-src 2>&1 | grep -e '^resolving ' -e '^  [^ ]'

# now with no forced host

ipsec addconn --verbose ipv4-default 2>&1 | grep -e '^resolving ' -e '^  [^ ]'
ipsec addconn --verbose ipv6-default 2>&1 | grep -e '^resolving ' -e '^  [^ ]'

# newoe case, peer is group (see newoe-20-ipv6)

ipsec addconn --verbose ipv4-src-group 2>&1 | grep -e '^resolving ' -e '^  [^ ]'
ipsec addconn --verbose ipv6-src-group 2>&1 | grep -e '^resolving ' -e '^  [^ ]'

# re-adding while route is up (see ikev1-hostpair-02)

ip -4 address add dev eth0     192.0.2.1/32
ip -6 address add dev eth0  2001:db8:0:2::1 nodad
../../guestbin/route.sh -4   add dev eth0       192.1.2.23 via       192.1.3.254 src       192.0.2.1
../../guestbin/route.sh -6   add dev eth0 2001:db8:1:2::23 via 2001:db8:1:3::254 src 2001:db8:0:2::1
../../guestbin/route.sh -4
../../guestbin/route.sh -6

ipsec addconn --verbose ipv4-src-group 2>&1 | grep -e '^resolving ' -e '^  [^ ]'
ipsec addconn --verbose ipv6-src-group 2>&1 | grep -e '^resolving ' -e '^  [^ ]'

../../guestbin/route.sh -4   del dev eth0       192.1.2.23 via       192.1.3.254 src       192.0.2.1
../../guestbin/route.sh -6   del dev eth0 2001:db8:1:2::23 via 2001:db8:1:3::254 src 2001:db8:0:2::1
ip -4 address del dev eth0     192.0.2.1/32
ip -6 address del dev eth0  2001:db8:0:2::1
../../guestbin/route.sh -4
../../guestbin/route.sh -6

# messed up default (see ipv6-addresspool-05-dual-stack)

../../guestbin/route.sh -6 del default
../../guestbin/route.sh -6 add default dev eth0 via fe80::1000:ff:fe32:64ba
../../guestbin/route.sh -6

ipsec addconn --verbose ipv6-src 2>&1 | grep -e '^resolving ' -e '^  [^ ]'
