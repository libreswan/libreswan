/testing/guestbin/swan-prep --hostkeys
iptables -F INPUT
iptables -F OUTPUT
# ensure that clear text does not get through
# block port 7 via ipsec to confirm IPsec only covers 17/1701
iptables -A OUTPUT -m policy --dir out --pol ipsec -p tcp --dport 7 -j REJECT
iptables -A OUTPUT -o eth1 -d 192.1.2.23 -m policy --dir out --pol none -p udp --dport 1701 -j REJECT
iptables -A OUTPUT -m policy --dir out --pol ipsec -j ACCEPT
iptables -A INPUT -i eth1 -s 192.1.2.23 -m policy --dir in --pol none -p udp --sport 1701 -j REJECT
iptables -A INPUT -m policy --dir in --pol ipsec -j ACCEPT
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add north-east-l2tp
../../guestbin/l2tpd.sh
ipsec auto --route north-east-l2tp
echo done
