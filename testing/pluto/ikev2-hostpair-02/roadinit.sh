/testing/guestbin/swan-prep --x509
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --impair retransmits
ipsec auto --add westnet-eastnet-ipv4-psk-ikev2
echo "initdone"
