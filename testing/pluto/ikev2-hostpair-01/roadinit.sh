/testing/guestbin/swan-prep --x509
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
ipsec auto --add westnet-eastnet-ipv4-psk-ikev2
ipsec whack --impair suppress_retransmits
echo "initdone"
