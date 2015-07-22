#arp -an

dig 3.1.0.192.in-addr.arpa. txt

: we expect that east can ping west
ping -n -c 1 -n 192.1.2.45

: we expect that this will result in a %drop, as 1.1 is not OE enabled.
ping -n -c 8 -n 192.0.1.1
ipsec eroute

#arp -s 192.1.2.45 10:00:00:64:64:45

: we expect that this will result in a tunnel, as 1.3 is OE enabled.
ping -n -c 8 -n 192.0.1.3

ipsec eroute
# arp -an

: the nether world according to pluto
: ==== cut ====
ipsec auto --status
: ==== tuc ====

: we expect that the resulting tunnel will not affect communication
: to hosts which are not OE enabled.
ping -n -c 8 -n 192.0.1.1

# ipsec look

: we further expect that we can continue to communicate with the outside
: interface of west.
ping -n -c 1 -n 192.1.2.45

ipsec eroute

# arp -an | sort -n

echo end

