: ==== start ====
route delete -net 192.0.1.0 netmask 255.255.255.0
route delete -net default
route add -net default gw 192.1.2.45

named

TESTNAME=food-groups-clear-or-oe-01
source /testing/pluto/bin/eastlocal.sh

echo end eastinit.sh

