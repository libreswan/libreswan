/testing/guestbin/swan-prep
valgrind --leak-check=full /usr/local/libexec/ipsec/pluto --config /etc/ipsec.conf &
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet
ipsec auto --status | grep westnet-eastnet
echo "initdone"
