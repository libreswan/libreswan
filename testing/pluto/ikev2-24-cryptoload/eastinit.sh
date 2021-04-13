/testing/guestbin/swan-prep
ipsec _stackmanager start
export PLUTO_CRYPTO_HELPER_DELAY=10
ipsec pluto --config /etc/ipsec.conf --leak-detective
../../guestbin/wait-until-pluto-started
ipsec auto --add multi
echo "initdone"
