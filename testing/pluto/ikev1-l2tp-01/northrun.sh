ipsec auto --up north-east-l2tp
echo "c server" > /var/run/xl2tpd/l2tp-control
sleep 5
# should be non-zero counters if l2tp worked
# workaround for diff err msg between fedora versions resulting in diff byte count
ipsec whack --trafficstatus | grep -v "inBytes=0" | sed "s/type=ESP.*$/[...]/"
: ==== cut ====
cat /tmp/xl2tpd.log
: ==== tuc ====
# testing passthrough of non-l2tp/ipsec traffic
echo quit | socat - TCP:192.0.2.254:7
../../guestbin/ip.sh address show dev ppp0 | sed "s/ qdisc.*$//"
echo done
