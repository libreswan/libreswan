../../guestbin/ipsec-look.sh
: ==== cut ====
ipsec auto --status
ipsec whack --shutdown
: ==== tuc ====
grep Totals /tmp/nss.log
cat /tmp/nss.log | grep C_ | sort -n -r -k 5 
echo "for nspr logs, look at the verbose console log in OUTPUT"
: ==== cut ====
cat /tmp/nspr.log
: ==== tuc ====
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
