: ==== start ====
# confirm that the network is alive
ping -n -c 4 192.0.2.254
# make sure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j DROP
# confirm with a ping to east-in
ping -n -c 4 192.0.2.254

ipsec setup start
/testing/pluto/basic-pluto-01/eroutewait.sh trap
ipsec whack --debug-all
ipsec auto --add westnet-eastnet-x509
ipsec auto --up  westnet-eastnet-x509

echo done

