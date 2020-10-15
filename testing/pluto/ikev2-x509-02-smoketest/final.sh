# confirm all verifications used the NSS IPsec profile and not TLS client/server profile
grep profile /tmp/pluto.log  | grep -v Starting
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
