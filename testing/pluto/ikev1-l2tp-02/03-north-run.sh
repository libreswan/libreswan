ipsec auto --up north-east-l2tp
# give the kernel messages time to appear
echo "c server" > /var/run/xl2tpd/l2tp-control ; sleep 5
../../guestbin/ping-once.sh --up 192.0.2.254
# should be non-zero counters if l2tp worked
# workaround for diff err msg between fedora versions resulting in diff byte count
ipsec whack --trafficstatus | grep -v "inBytes=0" | sed "s/type=ESP.*$/[...]/"
# testing passthrough of non-l2tp/ipsec traffic
 echo quit | socat - TCP:192.0.2.254:7
: ==== cut ====
cat /tmp/xl2tpd.log
: ==== tuc ====
../../guestbin/ip.sh address show dev ppp0 | sed "s/ qdisc.*$//"
echo done
