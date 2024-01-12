/testing/guestbin/swan-prep --x509
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
ipsec whack --impair revival
ipsec auto --add westnet-eastnet-ipv4-psk-ikev1
echo "initdone"
