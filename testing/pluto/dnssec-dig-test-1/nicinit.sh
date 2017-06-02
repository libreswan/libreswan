iptables -t nat -F
iptables -F
time /testing/guestbin/swan-prep --dnssec 2>&1
ls -lt /var/lib/unbound/
grep "root.key" /etc/unbound/unbound.conf
ls -lt /etc/systemd/system/unbound.service
ps -ax
echo done
: ==== end ====
