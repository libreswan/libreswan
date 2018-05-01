/testing/guestbin/swan-prep
# just start it so we try some resolv.conf rewriting
cp road-unbound.conf /etc/unbound/unbound.conf
unbound-control-setup > /dev/null 2>&1
unbound
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ipv4-psk-ikev2
echo "initdone"
