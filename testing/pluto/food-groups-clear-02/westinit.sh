: ==== start ====
# reset network configuration so that west thinks it is on a different
# subnet than east. Put it on a /27 (32-hosts)
# we don't screw with east, although we ought to.

named

ifdown eth1
ifconfig eth1 inet 192.1.2.45 netmask 255.255.255.224 up

# use the default route at the top of the netmask.
route add -net default gw 192.1.2.62

: try default route
ping -c 1 -n 192.1.2.62

: try hitting east before doing IPsec
ping -c 1 -n 192.1.2.23

ipsec start
/testing/pluto/bin/wait-until-policy-loaded

ipsec auto --add us-to-anyone
ipsec auto --route us-to-anyone
ipsec auto --replace clear
ipsec whack --listen
ipsec auto --route clear

: check out if .23 has proper TXT record.
dig 23.2.1.192.in-addr.arpa. txt


ipsec look

echo end

