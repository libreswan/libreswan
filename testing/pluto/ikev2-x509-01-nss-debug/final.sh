../../pluto/bin/ipsec-look.sh
: ==== cut ====
ipsec auto --status
ipsec whack --shutdown
: ==== tuc ====
cat /tmp/nspr.log
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
