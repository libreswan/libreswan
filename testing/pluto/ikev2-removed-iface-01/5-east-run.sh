../../guestbin/ip.sh address add 192.1.3.3/24 dev eth3
ipsec listen
ipsec auto --status | grep "[.][.][.]"
