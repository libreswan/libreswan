/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add east
../../guestbin/ping-once.sh --up -I 192.0.2.254 192.0.1.254 &
echo "initdone"
