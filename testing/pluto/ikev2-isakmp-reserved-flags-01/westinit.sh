: ==== start ====
TESTNAME=ikev2-isakmp-reserved-flags-01
source /testing/pluto/bin/westnlocal.sh

# confirm that the network is alive
ping -n -c 1 192.0.2.254
# make sure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j DROP
# confirm with a ping to east-in
ping -n -c 1 192.0.2.254

ipsec setup start
/testing/pluto/bin/wait-until-pluto-started

ipsec whack --whackrecord /var/tmp/ikev2.record
ipsec auto --add westnet--eastnet-ikev2
ipsec whack --debug-all --debug-crypt --impair-send-bogus-isakmp-flag
ipsec auto --status
echo "initdone"
