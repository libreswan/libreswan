ipsec auto --up north--east-l2tp
echo "c server" > /var/run/xl2tpd/l2tp-control
sleep 5
# should be non-zero counters if l2tp worked
ipsec whack --trafficstatus
: ==== cut ====
cat /tmp/xl2tpd.log
: ==== tuc ====
# testing passthrough conn
echo quit | nc 192.0.2.254 22
ip addr show dev ppp0 | sed "s/ qdisc.*$//"
echo done
