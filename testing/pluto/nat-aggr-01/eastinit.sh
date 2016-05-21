/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add northnet-eastnet-nat
: ==== cut ====
ipsec auto --status
ipsec klipsdebug --set rcv
ipsec klipsdebug --set verbose
: ==== tuc ====
echo "initdone"
