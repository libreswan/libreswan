../../guestbin/swan-prep --hostkeys
# confirm that the network is alive
../../guestbin/wait-until-alive 192.0.2.254 -I 192.0.1.254
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
echo "initdone"
