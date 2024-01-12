/testing/guestbin/swan-prep --x509
# confirm that the network is alive
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
ipsec auto --add roadnet-eastnet-ipv4-psk-ikev1
echo "initdone"
