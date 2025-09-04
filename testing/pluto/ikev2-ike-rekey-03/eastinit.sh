/testing/guestbin/swan-prep --nokeys
../../guestbin/ip.sh address show dev eth0 | grep 192.0.200.254 || ../../guestbin/ip.sh address add 192.0.200.254/24 dev eth0:1
../../guestbin/ip.sh address show dev eth0 | grep 192.0.201.254 || ../../guestbin/ip.sh address add 192.0.201.254/24 dev eth0:1
../../guestbin/ip.sh route show scope global | grep 192.0.100.0 || ip route add 192.0.100.0/24 via 192.1.2.45  dev eth1
../../guestbin/ip.sh route show scope global | grep 192.0.101.0 || ip route add 192.0.101.0/24 via 192.1.2.45  dev eth1
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add westnet-eastnet-ikev2c
ipsec add westnet-eastnet-ikev2b
ipsec add westnet-eastnet-ikev2a
echo "initdone"
