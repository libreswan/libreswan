/testing/guestbin/swan-prep --46 --hostkeys
# confirm that the network is alive
../../guestbin/ping-once.sh --up -I 2001:db8:1:2::45 2001:db8:1:2::23
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add v6-transport
ipsec whack --impair suppress_retransmits
echo "initdone"
