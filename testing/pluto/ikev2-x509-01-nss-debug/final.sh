../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh
grep Totals /tmp/nss.log
cat /tmp/nss.log | grep C_ | sort -n -r -k 5 
echo "for nspr logs, look at the verbose console log in OUTPUT"
: ==== cut ====
cat /tmp/nspr.log
: ==== tuc ====
