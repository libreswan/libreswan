: ==== cut ====
ipsec auto --status
: ==== tuc ====
ipsec stop
grep -E -i "IKE|ipsec-" /var/log/audit/audit.log
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
