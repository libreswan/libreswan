: ==== start ====
route delete -net 192.0.1.0 netmask 255.255.255.0
route delete -net default
route add -net default gw 192.1.2.45

ipsec start
/testing/pluto/bin/wait-until-pluto-started

/testing/pluto/basic-pluto-01/eroutewait.sh trap

ipsec look
ipsec auto --add clear
ipsec whack --listen
ipsec eroute
ipsec auto --route clear
ipsec eroute

echo end

