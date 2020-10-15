hostname | grep east > /dev/null && grep -E "no Certificate Authority in NSS Certificate DB|authentication using rsasig failed" /tmp/pluto.log
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
