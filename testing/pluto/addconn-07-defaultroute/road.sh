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

./run.sh left=%defaultroute right=192.1.2.23
./run.sh left=%defaultroute right=2001:db8:1:2::23

# simple case but with clash

./run.sh left=%defaultroute4 right=2001:db8:1:2::23 # fail
./run.sh left=%defaultroute6 right=192.1.2.23       # fail

# defaultroute-direct-ip

./run.sh left=%defaultroute leftnexthop=%direct right=192.1.2.23
./run.sh left=%defaultroute leftnexthop=%direct right=2001:db8:1:2::23

# simple case, peer unknown

./run.sh left=%defaultroute right=%any
./run.sh hostaddrfamily=ipv4 left=%defaultroute right=%any
./run.sh hostaddrfamily=ipv6 left=%defaultroute right=%any

# simple case, can't load as to-any

./run.sh left=%any right=%any
./run.sh hostaddrfamily=ipv4 left=%any right=%any
./run.sh hostaddrfamily=ipv4 left=%any right=%any

# peer unknown (failing in libreswan up to 3.21 in specific scenarios)

./run.sh left=%defaultroute leftnexthop=%defaultroute right=%any
./run.sh hostaddrfamily=ipv4 left=%defaultroute leftnexthop=%defaultroute right=%any
./run.sh hostaddrfamily=ipv6 left=%defaultroute leftnexthop=%defaultroute right=%any

# newoe case, peer is group (see newoe-20-ipv6)

./run.sh hostaddrfamily=ipv4 left=%defaultroute right=%group
./run.sh hostaddrfamily=ipv6 left=%defaultroute right=%group

# re-adding while route is up (see ikev1-hostpair-02)

ip -4 address add dev eth0     192.0.2.1/32
ip -6 address add dev eth0  2001:db8:0:2::1 nodad
../../guestbin/ip.sh -4 route   add dev eth0       192.1.2.23 via       192.1.3.254 src       192.0.2.1
../../guestbin/ip.sh -6 route   add dev eth0 2001:db8:1:2::23 via 2001:db8:1:3::254 src 2001:db8:0:2::1
../../guestbin/ip.sh -4 route
../../guestbin/ip.sh -6 route

./run.sh hostaddrfamily=ipv4 left=%defaultroute right=%group
./run.sh hostaddrfamily=ipv6 left=%defaultroute right=%group

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

./run.sh left=%defaultroute right=2001:db8:1:2::23
