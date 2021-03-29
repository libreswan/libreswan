ipsec stop
rm -f /etc/ipsec.d/*.*
umount /etc/ipsec.d
test -f /var/run/pluto/sshd.pid && kill -9 `cat /var/run/pluto/sshd.pid` >/dev/null
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
