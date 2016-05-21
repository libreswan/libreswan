: ==== start ====
route delete -net 192.0.1.0 netmask 255.255.255.0
route delete -net default
route add -net default gw 192.1.2.254

named

ipsec start
/testing/pluto/bin/wait-until-pluto-started

ipsec look
ipsec auto --add clear
ipsec auto --add private-or-clear
ipsec auto --delete packetdefault
ipsec whack --listen
ipsec auto --route clear
ipsec auto --route private-or-clear
ipsec eroute

echo end

