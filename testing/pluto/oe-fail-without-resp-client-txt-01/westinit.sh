: ==== start ====
named
route delete -net 192.0.2.0 netmask 255.255.255.0
route delete -net default
route add -net default gw 192.1.2.23

# for debugging, we sometimes want to force this ARP entry.
# arp -s 192.1.2.23 10:00:00:64:64:23

ipsec start
/testing/pluto/bin/wait-until-pluto-started

# passive OE only.
ipsec auto --add us-to-anyone

/testing/pluto/basic-pluto-01/eroutewait.sh trap

: let my people go - let all packets not otherwise dealt with out in the
: clear, despite stoopid routing tricks.
ipsec auto --delete packetdefault
ipsec manual --up let-my-people-go
