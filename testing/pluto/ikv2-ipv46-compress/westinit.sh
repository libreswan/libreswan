/testing/guestbin/swan-prep --nokeys --46
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
../../guestbin/nftable-westneteastnet-ipsec-only.nft
../../guestbin/ping-once.sh --down -I 192.0.1.254 192.0.2.254
ipsec start
../../guestbin/wait-until-pluto-started
echo "initdone"
