/testing/guestbin/swan-prep
# just start it so we try some resolv.conf rewriting
unbound
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ipv4-psk-ikev2
echo "initdone"
