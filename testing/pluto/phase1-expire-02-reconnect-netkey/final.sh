ipsec look
: ==== cut ====
ipsec auto --status
# for netkey, show policies
echo "ip xfrm policy"
ip xfrm policy
echo "ip xfrm state"
ip xfrm state
: ==== tuc ====
if [ -n "`ls /tmp/core* 2>/dev/null`" ]; then echo CORE FOUND; mv /tmp/core* OUTPUT/; fi
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
