/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
# should be unoriented
ipsec auto --status | grep westnet-eastnet-ikev2 | grep "[.][.][.]"
../../guestbin/ip.sh address add 192.1.2.24/24 dev eth1
ipsec whack --listen
# should be oriented
ipsec auto --status | grep westnet-eastnet-ikev2 | grep "[.][.][.]"
echo "initdone"
