iptables -t nat -F
iptables -F
iptables -t nat -L
time /testing/guestbin/swan-prep --dnssec
ps -ax
ls -lt /var/lib/unbound/
grep "root.key" /etc/unbound/unbound.conf
echo done
: ==== end ====
