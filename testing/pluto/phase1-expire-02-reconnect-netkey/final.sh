ipsec look
: ==== cut ====
ipsec auto --status
# for netkey, show policies
echo "ip xfrm policy"
ip xfrm policy
echo "ip xfrm state"
ip xfrm state
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
