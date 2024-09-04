/testing/guestbin/swan-prep
# confirm that the network is alive
../../guestbin/wait-until-alive -I 192.0.1.254 192.0.2.254
# ensure that clear text does not get through
../../guestbin/nftable-westneteastnet-ipsec-only.nft
# confirm clear text does not get through
../../guestbin/ping-once.sh --down -I 192.0.1.254 192.0.2.254
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ipv4-psk-ikev2
ipsec auto --status |grep westnet-eastnet-ipv4-psk-ikev2
ipsec whack --impair suppress-retransmits
echo "initdone"
