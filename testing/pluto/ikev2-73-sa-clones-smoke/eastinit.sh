/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-clones
ipsec auto --status | grep westnet-eastnet-clones
ipsec whack --impair suppress_retransmits
echo "initdone"
