# nic 00-nic-init.sh

nic# #!/bin/sh
nic# iptables -t nat -F
nic# iptables -F
nic# echo done
nic# : ==== end ====

# east 01-alpineeast-init.sh

east# /testing/guestbin/prep.sh
east# 
east# ipsec initnss
east# /testing/x509/import.sh real/mainca/east.p12
east# /testing/x509/import.sh real/mainca/north.end.cert
east# /testing/x509/import.sh real/mainca/road.end.cert
east# 
east# ipsec start
east# ../../guestbin/wait-until-pluto-started
east# ipsec add l2tp-north-to-east-on-east
east# ipsec add l2tp-distraction-on-east
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

north# /testing/guestbin/prep.sh
north# 
north# ipsec initnss
north# /testing/x509/import.sh real/mainca/north.p12
north# /testing/x509/import.sh real/mainca/east.end.cert
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
north# ipsec add l2tp-north-to-east-on-north
north# 
north# ../../guestbin/l2tpd.sh
north# ipsec route l2tp-north-to-east-on-north
north# echo done

# north 03-alpinenorth-up.sh

north# ipsec up l2tp-north-to-east-on-north # sanitize-retransmits
north# 
north# # give the kernel messages time to appear
north# echo "c server" > /var/run/xl2tpd/l2tp-control ; sleep 5
north# ../../guestbin/ping-once.sh --up 192.0.2.254
north# 
north# ipsec whack --trafficstatus | grep -v "inBytes=0" | sed "s/type=ESP.*$/[...]/"

# final final.sh

final# ipsec _kernel state
final# ipsec _kernel policy
final# grep 'Result using RFC 3947' /tmp/pluto.log

