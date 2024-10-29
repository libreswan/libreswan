# show nflog global ipsec-all rules
nft list ruleset
ipsec auto --up westnet-eastnet-ikev2

# suppress job monitoring; specify packet count
../../guestbin/tcpdump.sh --start -c 4 -i nflog:50

../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254

# wait for count to reach tcpdump then dump it; dump everything
../../guestbin/tcpdump.sh --wait -i nflog:50 --

echo done
