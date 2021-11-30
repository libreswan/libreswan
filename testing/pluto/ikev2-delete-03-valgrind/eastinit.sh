/testing/guestbin/swan-prep
valgrind  --trace-children=yes --leak-check=full ipsec pluto --nofork --config /etc/ipsec.conf &
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
echo "initdone"
