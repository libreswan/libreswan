# replay-window will show up as 0 when ESN is enabled due to kernel bug.
ip xfrm state |grep replay-window
: ==== cut ====
ipsec auto --status
ipsec look
: ==== tuc ====
if [ -n "`ls /tmp/core* 2>/dev/null`" ]; then echo CORE FOUND; mv /tmp/core* OUTPUT/; fi
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
