/testing/guestbin/swan-prep --46
ipsec start
../../guestbin/wait-until-pluto-started

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

ipsec add defaultroute-ipv4
ipsec connectionstatus defaultroute-ipv4 | grep ' host: '
ipsec add defaultroute-ipv6
ipsec connectionstatus defaultroute-ipv6 | grep ' host: '

# simple case but with clash

ipsec add defaultroute4-ipv6 # fail
ipsec add defaultroute6-ipv4 # fail

# defaultroute-direct-ip

ipsec add defaultroute-direct-ipv4
ipsec connectionstatus defaultroute-direct-ipv4 | grep ' host: '
ipsec add defaultroute-direct-ipv6
ipsec connectionstatus defaultroute-direct-ipv6 | grep ' host: '

# simple case, forced family

ipsec add hostaddrfamily-ipv4-defaultroute-any
ipsec connectionstatus hostaddrfamily-ipv4-defaultroute-any | grep ' host: '
ipsec add hostaddrfamily-ipv6-defaultroute-any
ipsec connectionstatus hostaddrfamily-ipv6-defaultroute-any | grep ' host: '

# newoe case, peer is group (see newoe-20-ipv6)

ipsec add hostaddrfamily-ipv4-defaultroute-group
ipsec connectionstatus hostaddrfamily-ipv4-defaultroute-group | grep ' host: '
ipsec add hostaddrfamily-ipv6-defaultroute-group
ipsec connectionstatus hostaddrfamily-ipv6-defaultroute-group | grep ' host: '

# re-adding while route is up (see ikev1-hostpair-02)

ip -4 address add dev eth0     192.0.2.1/32
ip -6 address add dev eth0  2001:db8:0:2::1 nodad
../../guestbin/ip.sh -4 route   add dev eth0       192.1.2.23 via       192.1.3.254 src       192.0.2.1
../../guestbin/ip.sh -6 route   add dev eth0 2001:db8:1:2::23 via 2001:db8:1:3::254 src 2001:db8:0:2::1
../../guestbin/ip.sh -4 route
../../guestbin/ip.sh -6 route

ipsec add hostaddrfamily-ipv4-defaultroute-group
ipsec connectionstatus hostaddrfamily-ipv4-defaultroute-group | grep ' host: '
ipsec add hostaddrfamily-ipv6-defaultroute-group
ipsec connectionstatus hostaddrfamily-ipv6-defaultroute-group | grep ' host: '

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

ipsec add defaultroute-ipv6
ipsec connectionstatus defaultroute-ipv6 | grep ' host: '
