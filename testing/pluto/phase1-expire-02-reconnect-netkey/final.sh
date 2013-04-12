: ==== cut ====
ipsec auto --status
# for netkey, show policies
echo "ip xfrm policy"
ip xfrm policy
echo "ip xfrm state"
ip xfrm state
: ==== tuc ====
if [ -f /tmp/core ]; then echo CORE FOUND; mv /tmp/core /var/tmp; fi
: ==== end ====
