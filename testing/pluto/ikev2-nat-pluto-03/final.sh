# this should show encap tunnel on both ends
ip xfrm state |grep encap
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
