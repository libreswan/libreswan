/testing/guestbin/swan-prep --46
# confirm that the network is alive
ping6 -W 16 -w 5 -n -q -c 2 2001:db8:1:2::23
# ensure that clear text does not get through
../../guestbin/nftable-westneteastnet-ipsec-only.nft
# confirm clear text does not get through
ping6 -W 16 -w 5 -n -q -c 2 -I 2001:db8:1:2::45 2001:db8:1:2::23
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add v6-tunnel
ipsec auto --status
echo "initdone"
