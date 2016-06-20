: ==== start ====
route delete -net 192.0.2.0 netmask 255.255.255.0
route delete -net default
route add -net default gw 192.1.2.23

arp -an

ipsec start
/testing/pluto/bin/wait-until-pluto-started

ipsec manual --up westnet-east-pass
ipsec manual --up west-east-pass

ipsec look

echo end

