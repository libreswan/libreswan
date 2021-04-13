#ipsec stop
test -f /var/run/pluto/sshd.pid && kill -9 `cat /var/run/pluto/sshd.pid` >/dev/null
