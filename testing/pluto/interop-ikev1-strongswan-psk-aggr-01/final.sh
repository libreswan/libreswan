# confirm the right ID types were sent/received
hostname | grep east > /dev/null &&  grep "ID type" /tmp/pluto.log | sort | uniq
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
