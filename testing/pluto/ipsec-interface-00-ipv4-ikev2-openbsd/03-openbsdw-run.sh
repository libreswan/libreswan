#
# establish the IKE SA using IKED
#

ifconfig sec1 create
ifconfig sec1 inet 192.0.1.251/24 192.0.2.254
ifconfig sec1 up

../../guestbin/iked.sh start

sleep 10 # something better?

../../guestbin/ping-once.sh --up -I 192.0.1.251 192.0.2.254

ifconfig sec1
../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh

../../guestbin/iked.sh stop

ifconfig sec1 destroy

#
# establish the IKE SA using Libreswan
#

ipsec start
../../guestbin/wait-until-pluto-started

ipsec add west

ifconfig sec1
../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh

ipsec up west

ifconfig sec1
../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh

../../guestbin/tcpdump.sh --start -i sec1

../../guestbin/ping-once.sh --up -I 192.0.1.251 192.0.2.254

../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh

../../guestbin/tcpdump.sh --stop -i sec1

ipsec down west
ipsec delete west
