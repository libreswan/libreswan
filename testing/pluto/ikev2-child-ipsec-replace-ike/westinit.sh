/testing/guestbin/swan-prep --nokeys
../../guestbin/ip.sh address add 192.0.100.254/24 dev eth0:1
../../guestbin/ip.sh route add 192.0.200.0/24 via 192.1.2.23  dev eth1

ipsec start
../../guestbin/wait-until-pluto-started

ipsec whack --impair suppress_retransmits

ipsec add westnet-eastnet-ikev2a
ipsec add westnet-eastnet-ikev2b

echo "initdone"
