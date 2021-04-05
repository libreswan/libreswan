ipsec stop
grep -E -i "IKE|ipsec-" /var/log/audit/audit.log
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
