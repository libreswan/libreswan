ipsec look
grep '^connection from' /tmp/pluto.log
ipsec stop
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
