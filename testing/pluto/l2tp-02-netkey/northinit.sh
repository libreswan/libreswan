/testing/guestbin/swan-prep
iptables -F INPUT
iptables -F OUTPUT
# make sure that clear text does not get through
iptables -A INPUT -i eth1 -d 192.1.2.23/32 -p udp --dport 1701 -j LOGDROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
ipsec start
/testing/pluto/bin/wait-until-pluto-started
# passthrough not needed with netkey
ipsec auto --add north-east-l2tp
#ipsec auto --add north-east-pass
#ipsec auto --route north-east-pass
(cd /tmp && xl2tpd -D 2>/tmp/xl2tpd.log 1>&2) &
ipsec auto --route north-east-l2tp
echo done
