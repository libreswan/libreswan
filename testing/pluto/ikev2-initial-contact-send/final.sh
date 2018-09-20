ipsec whack --trafficstatus
../../pluto/bin/ipsec-look.sh
# one INITIAL_CONTACT payload is sent, in the single IKE_AUTH
# on east, shows up twice in log for a single payload
# on west, shows up once in log for a single payload
grep INITIAL /tmp/pluto.log
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
