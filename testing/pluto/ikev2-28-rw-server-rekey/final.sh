hostname | grep east > /dev/null && ipsec whack --rekey-ipsec --name road-eastnet-nonat
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
