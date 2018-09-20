/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --impair delete-on-retransmit
ipsec auto --add westnet-eastnet-ipv4-psk-ikev1
echo "initdone"
