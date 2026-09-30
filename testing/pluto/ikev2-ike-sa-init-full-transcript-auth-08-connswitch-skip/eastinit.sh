/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add weakconn
ipsec add strongconn
ipsec whack --impair suppress_retransmits
echo "initdone"
