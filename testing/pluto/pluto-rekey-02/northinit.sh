/testing/guestbin/swan-prep --hostkeys
ifconfig eth1 192.1.3.32 netmask 255.255.255.0
route add -net default gw 192.1.3.254
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add northnet-eastnet-nat
ipsec whack --impair suppress_retransmits
echo "initdone"
