: ==== start ====

iptables -D INPUT -s 192.1.2.23/32 -d 0/0 -j DROP
iptables -D OUTPUT -d 192.1.2.23/32 -s 0/0 -j DROP

# remove the block
iptables -F

# Tunnel should be back up now
ipsec eroute
echo done

TESTNAME=dpd-06
source /testing/pluto/bin/westlocal.sh

ipsec setup start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add west-east

ipsec whack --debug-dpd --debug-control


