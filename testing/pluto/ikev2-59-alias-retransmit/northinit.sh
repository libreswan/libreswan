/testing/guestbin/swan-prep
rm -fr /var/run/pluto/pluto.pid
ipsec _stackmanager start --netkey
export PLUTO_CRYPTO_HELPER_DELAY=2
ipsec pluto --config /etc/ipsec.conf
../../guestbin/wait-until-pluto-started
ipsec auto --add north-eastnets
echo "initdone"
