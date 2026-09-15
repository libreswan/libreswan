nft list ruleset
ipsec up westnet-eastnet-nflog # sanitize-retransmits
nft list ruleset
ipsec up west-east-nflog # sanitize-retransmits
nft list ruleset

# suppress job monitoring; specify packet count
../../guestbin/tcpdump.sh --start -c 4 -i nflog:50

../../guestbin/ping-once.sh --up -I 192.1.2.45 192.1.2.23
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
../../guestbin/ping-once.sh --up -I 192.1.2.45 192.1.2.23
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254

ipsec down westnet-eastnet-nflog # sanitize-retransmits
nft list ruleset
ipsec down west-east-nflog # sanitize-retransmits
nft list ruleset

# wait for count to reach tcpdump then dump it
../../guestbin/tcpdump.sh --wait -i nflog:50 --

echo done
