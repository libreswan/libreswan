: ==== start ====
set -u
route delete -net 192.0.1.0 netmask 255.255.255.0
route delete -net default
route add -net default gw 192.1.2.45

# start the local name server
named

# verify that we have some dns data!
dig sunrise-oe.uml.freeswan.org a
dig 45.2.1.192.in-addr.arpa. txt

netstat -rne

ipsec start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add simulate-OE-east-west-1
/testing/pluto/basic-pluto-01/eroutewait.sh trap
ipsec auto --route simulate-OE-east-west-1

: ==== cut ====
ipsec look
: ==== tuc ====

