ipsec auto --up north-east-l2tp
echo "c server" > /var/run/xl2tpd/l2tp-control
sleep 5
ipsec look
: ==== cut ====
cat /tmp/xl2tpd.log
: ==== tuc ====
ping -c 4 -n 192.0.2.254
# testing passthrough plaintext
echo quit | nc 192.0.2.254 22
ip addr show dev ppp0 | sed "s/ qdisc.*$//"
echo done
