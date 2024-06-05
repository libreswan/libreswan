/testing/guestbin/swan-prep --46

../../guestbin/ip.sh -4 route
../../guestbin/ip.sh -6 route

# %any
../../guestbin/ip.sh -4 route get to 0.0.0.0
../../guestbin/ip.sh -6 route get to ::

# gateway
../../guestbin/ip.sh -4 route get to 192.1.3.254
../../guestbin/ip.sh -6 route get to 2001:db8:1:3::254

# peer
../../guestbin/ip.sh -4 route get to 192.1.2.23
../../guestbin/ip.sh -6 route get to 2001:db8:1:2::23

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
../../guestbin/ip.sh -4 route   add dev eth0       192.1.2.23 via       192.1.3.254 src       192.0.2.1
../../guestbin/ip.sh -6 route   add dev eth0 2001:db8:1:2::23 via 2001:db8:1:3::254 src 2001:db8:0:2::1
../../guestbin/ip.sh -4 route
../../guestbin/ip.sh -6 route

ipsec addconn --verbose ipv4-src-group 2>&1 | grep -e '^resolving ' -e '^  [^ ]'
ipsec addconn --verbose ipv6-src-group 2>&1 | grep -e '^resolving ' -e '^  [^ ]'

../../guestbin/ip.sh -4 route   del dev eth0       192.1.2.23 via       192.1.3.254 src       192.0.2.1
../../guestbin/ip.sh -6 route   del dev eth0 2001:db8:1:2::23 via 2001:db8:1:3::254 src 2001:db8:0:2::1
ip -4 address del dev eth0     192.0.2.1/32
ip -6 address del dev eth0  2001:db8:0:2::1
../../guestbin/ip.sh -4 route
../../guestbin/ip.sh -6 route

# messed up default (see ipv6-addresspool-05-dual-stack)

../../guestbin/ip.sh -6 route del default
../../guestbin/ip.sh -6 route add default dev eth0 via fe80::1000:ff:fe32:64ba
../../guestbin/ip.sh -6 route

ipsec addconn --verbose ipv6-src 2>&1 | grep -e '^resolving ' -e '^  [^ ]'
