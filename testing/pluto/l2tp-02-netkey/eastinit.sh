/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
# pass non-l2tp plaintext, netkey needs no passthrough conns
ipsec auto --add any-east-l2tp
#ipsec auto --add north-east-pass
#ipsec auto --route north-east-pass
# make sure that clear text does not get through
iptables -A INPUT -i eth1 -d 192.1.2.23/32 -p udp --dport 1701 -j LOGDROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
(cd /tmp && xl2tpd -D 2>/tmp/xl2tpd.log 1>&2 ) &
echo done
