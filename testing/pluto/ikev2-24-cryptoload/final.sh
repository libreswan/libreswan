../../pluto/bin/ipsec-look.sh
ipsec stop
# on east ipsec stop will not work pluto is not started with ipsec start
pidof pluto && kill `pidof pluto`
grep -e leak /tmp/pluto.log | grep -v -e '|'
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
