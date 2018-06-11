# let road and north wait for east to show tunnels before shutting down
hostname | grep road > /dev/null && sleep 5
hostname | grep north > /dev/null && sleep 5
hostname | grep east > /dev/null && ipsec whack --trafficstatus
: ==== cut ====
ipsec look # ../../pluto/bin/ipsec-look.sh
ipsec auto --status
ipsec stop
: ==== tuc ====
grep "^leak" /tmp/pluto.log
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
