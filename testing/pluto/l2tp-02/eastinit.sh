/testing/guestbin/swan-prep
ipsec _stackmanager start
/usr/local/libexec/ipsec/pluto --config /etc/ipsec.conf
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add any--east-l2tp
ipsec auto --add north--east-pass
ipsec auto --route north--east-pass
ipsec whack --debug-control --debug-controlmore --debug-natt
# make sure that clear text does not get through
iptables -A INPUT  -i eth1 -d 192.1.2.23 -p udp --dport 1701 -j REJECT
iptables -A OUTPUT -o eth1 -s 192.1.2.23 -p udp --sport 1701 -j REJECT
(cd /tmp && xl2tpd -c /testing/pluto/l2tp-01/east.l2tpd.conf -D 2>/tmp/xl2tpd.log ) &
echo "initdone"
