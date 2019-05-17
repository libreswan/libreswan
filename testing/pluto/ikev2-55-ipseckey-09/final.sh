# east should have two public keys. including road fetched from dns
ipsec auto --listpubkeys
ipsec whack --trafficstatus
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
