route delete -net 192.0.1.0 netmask 255.255.255.0
route delete -net default
route add -net default gw 192.1.2.45

# start the local name server
named

# verify that we have some dns data!
dig sunrise-oe.uml.freeswan.org a

netstat -rne

ipsec setup start

/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add private
ipsec whack --listen
ipsec auto --route private

: ==== cut ====
ipsec look
: ==== tuc ====

#route delete -net 192.1.2.0 netmask 255.255.255.0 dev ipsec0

# this eroute was added because we were suspicous that KLIPS might be
# catching packets and not know what do to with them since they matched
# no eroute (and thus weren't eligble for the port-500 hole). This belief
# proved to be wrong.
#ipsec eroute --add --eraf inet --src 192.1.2.23/32 --dst 0.0.0.0/0 --said %pass
#ipsec klipsdebug --set tunnel

#ipsec look

#(echo $$ >/tmp/eth1.pid   && tcpdump -i eth1   -l -n -p -s 1600 > /tmp/eth1.txt) &
#(echo $$ >/tmp/ipsec0.pid && tcpdump -i ipsec0 -l -n -p -s 1600 > /tmp/ipsec0.txt) &






