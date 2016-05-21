: ==== start ====
set -u
route delete -net 192.0.1.0 netmask 255.255.255.0
route delete -net default
route add -net default gw 192.1.2.45

# start the local name server
named

# verify that we have some dns data!
dig sunrise-oe.uml.freeswan.org a

netstat -rne

ipsec start
/testing/pluto/bin/wait-until-pluto-started


: ==== cut ====
ipsec look
: ==== tuc ====
