mount -o rw,remount /usr/src
source japan-init.sh
/testing/pluto/bin/wait-until-pluto-started
source japan-run.sh
ipsec whack --debug-oppo --debug-control --debug-controlmore

sleep 5
ping -n -c 1 1.2.3.4
echo route2
ipsec eroute
sleep 5
ping -n -c 1 192.0.2.2
echo route1
ipsec eroute
sleep 3
ping -n -c 1 192.0.2.2
echo route2
ipsec eroute
sleep 3
ping -n -c 1 1.2.3.4
echo route2
ipsec eroute

#ipsec setup stop
