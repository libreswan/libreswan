# nic 00-nic-init.sh

nic# #!/bin/sh
nic# iptables -t nat -F
nic# iptables -F
nic# echo done
nic# : ==== end ====

# east 01-alpineeast-init.sh

east# /testing/guestbin/prep.sh --hostkeys
east# 
east# ipsec start
east# ../../guestbin/wait-until-pluto-started
east# ipsec add any-east-l2tp
east# 
east# # ensure that clear text does not get through
east# iptables -A INPUT  -i eth1 -d 192.1.2.23 -m policy --dir in --pol none -p udp --dport 1701 -j REJECT
east# iptables -A INPUT -m policy --dir in --pol ipsec -j ACCEPT
east# iptables -A OUTPUT -o eth1 -s 192.1.2.23 -m policy --dir out --pol none -p udp --sport 1701 -j REJECT
east# iptables -A OUTPUT -m policy --dir out --pol ipsec -j ACCEPT
east# 
east# ../../guestbin/l2tpd.sh
east# ../../guestbin/echo-server.sh -tcp -4 7 -daemon
east# echo done

# north 02-alpinenorth-init.sh

north# /testing/guestbin/prep.sh --hostkeys
north# 
north# # ensure that clear text does not get through
north# # block port 7 via ipsec to confirm IPsec only covers 17/1701
north# iptables -F INPUT
north# iptables -F OUTPUT
north# iptables -A OUTPUT -m policy --dir out --pol ipsec -p tcp --dport 7 -j REJECT
north# iptables -A OUTPUT -o eth1 -d 192.1.2.23 -m policy --dir out --pol none -p udp --dport 1701 -j REJECT
north# iptables -A OUTPUT -m policy --dir out --pol ipsec -j ACCEPT
north# iptables -A INPUT -i eth1 -s 192.1.2.23 -m policy --dir in --pol none -p udp --sport 1701 -j REJECT
north# iptables -A INPUT -m policy --dir in --pol ipsec -j ACCEPT
north# 
north# ipsec start
north# ../../guestbin/wait-until-pluto-started
north# ipsec add north-east-l2tp
north# 
north# ../../guestbin/l2tpd.sh
north# ipsec route north-east-l2tp
north# echo done

# north 03-alpinenorth-run.sh

north# ipsec up north-east-l2tp # sanitize-retransmits
north# 
north# echo "c server" > /var/run/xl2tpd/l2tp-control
north# sleep 10
north# 
north# # should be non-zero counters if l2tp worked
north# # workaround for diff err msg between fedora versions resulting in diff byte count
north# ipsec whack --trafficstatus | grep -v "inBytes=0" | sed "s/type=ESP.*$/[...]/"
north# 
north# : ==== cut ====
north# cat /tmp/xl2tpd.log
north# : ==== tuc ====
north# 
north# # testing passthrough of non-l2tp/ipsec traffic
north# echo quit | socat - TCP:192.0.2.254:7
north# ../../guestbin/ip.sh address show dev ppp0 | sed -e 's/ qdisc.*$//' -e '/inet6/,$ d'
north# echo done

# final final.sh

final# ipsec _kernel state
final# ipsec _kernel policy
final# grep 'Result using RFC 3947' /tmp/pluto.log

