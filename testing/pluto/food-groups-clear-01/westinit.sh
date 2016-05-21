: ==== start ====
route delete -net 192.0.2.0 netmask 255.255.255.0
route delete -net default
route add -net default gw 192.1.2.23

ipsec start
/testing/pluto/bin/wait-until-pluto-started

/testing/pluto/basic-pluto-01/eroutewait.sh trap

ipsec auto --up westnet-east-pass
ipsec look

echo end

