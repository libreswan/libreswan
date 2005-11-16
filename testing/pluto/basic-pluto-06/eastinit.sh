# make sure that packets don't sneak in
iptables -A INPUT -i eth1 -s 192.0.3.0/24 -d 0.0.0.0/0 -j DROP

ipsec setup start
ipsec klipsdebug --all
ipsec whack --debug-all
ipsec auto --add westnet-eastnet-x509
/testing/pluto/basic-pluto-01/eroutewait.sh trap
