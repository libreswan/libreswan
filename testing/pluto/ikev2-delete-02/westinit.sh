/testing/guestbin/swan-prep

# confirm that the network is alive
ping -n -c 2 -I 192.0.1.254 192.0.2.254

# make sure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j DROP
# confirm with a ping to east-in
ping -n -c 1 -I 192.0.1.254 192.0.2.254

ipsec setup stop
/usr/local/libexec/ipsec/_stackmanager stop
/usr/local/libexec/ipsec/_stackmanager start
/usr/local/libexec/ipsec/pluto --config /etc/ipsec.conf
/testing/pluto/bin/wait-until-pluto-started

ipsec whack --whackrecord /var/tmp/ikev2.record
ipsec auto --add west-east-delete1
ipsec auto --status
ipsec whack --debug-control --debug-controlmore --debug-parsing --debug-crypt

echo "initdone"
