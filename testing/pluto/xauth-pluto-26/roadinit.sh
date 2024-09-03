/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
../../guestbin/block-non-ipsec.sh
ipsec auto --add road-east
ipsec whack --impair suppress_retransmits
echo initdone
