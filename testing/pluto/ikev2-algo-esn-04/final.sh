# replay-window will show up as 0 when ESN is enabled due to kernel bug.
ip xfrm state |grep replay-window
: ==== cut ====
ipsec auto --status
ipsec look # ../../pluto/bin/ipsec-look.sh
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
