#ipsec stop
test -f /var/run/pluto/sshd.pid && kill -9 `cat /var/run/pluto/sshd.pid` >/dev/null
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
