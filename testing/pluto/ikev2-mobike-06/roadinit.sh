/testing/guestbin/swan-prep --nokeys
../../guestbin/ip-route.sh del default
../../guestbin/ip.sh address del 192.1.33.222/24 dev eth0 2>/dev/null
sleep 2
../../guestbin/ip.sh address add 192.1.3.209/24 dev eth0 2>/dev/null
../../guestbin/ip-route.sh add default via 192.1.3.254
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add road-eastnet
echo "initdone"
