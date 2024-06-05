/testing/guestbin/swan-prep
ip tunnel add test0 mode gre local 192.1.2.45 remote 192.1.2.23
../../guestbin/ip.sh address add 172.29.1.1/24 dev test0
ip link set dev test0 up
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add test1
ipsec auto --add test2
ipsec auto --add test3
