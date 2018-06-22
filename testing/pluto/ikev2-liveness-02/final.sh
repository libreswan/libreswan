# east should have restarted and re-established the tunnel
ipsec whack --trafficstatus
# can be seen on east logs
hostname | grep west > /dev/null || grep "IKEv2 liveness:" /tmp/pluto.log
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
