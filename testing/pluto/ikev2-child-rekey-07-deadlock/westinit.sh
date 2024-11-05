/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair revival
ipsec whack --impair suppress_retransmits
ipsec whack --impair helper_thread_delay:0
ipsec auto --add west-east
sleep 4
echo "initdone"
