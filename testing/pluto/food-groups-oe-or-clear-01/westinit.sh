named
route delete -net 192.0.2.0 netmask 255.255.255.0
route delete -net default
route add -net default gw 192.1.2.23

# for debugging, we sometimes want to force this ARP entry.
# arp -s 192.1.2.23 10:00:00:64:64:23

ping -n -c 4 192.0.1.3

ipsec setup start

: wait for packetdefault to show up
/testing/pluto/basic-pluto-01/eroutewait.sh trap

ipsec eroute

# passive OE only.
ipsec auto --add us-to-anyone

: let my people go - let all packets not otherwise dealt with out in the
: clear, despite stoopid routing tricks.
ipsec auto --delete packetdefault
ipsec manual --up let-my-people-go

#ipsec look

# look for matching kill in *final.sh
#(echo $$ >/tmp/eth1.pid   && tcpdump -i eth1   -l -n -p -s 1600 > /tmp/eth1.txt) &
#(echo $$ >/tmp/ipsec0.pid && tcpdump -i ipsec0 -l -n -p -s 1600 > /tmp/ipsec0.txt) &

