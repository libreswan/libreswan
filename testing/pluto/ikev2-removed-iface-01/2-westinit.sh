/testing/guestbin/swan-prep --nokeys
ip tunnel add eth3 mode gre local 192.1.2.45 remote 192.1.2.23
../../guestbin/ip.sh address add 192.1.3.2/24 dev eth3
../../guestbin/ip.sh link set dev eth3 up
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add test1
ipsec auto --add test2
ipsec auto --add test3
ipsec auto --status | grep interface
ipsec auto --status | grep "[.][.][.]"
