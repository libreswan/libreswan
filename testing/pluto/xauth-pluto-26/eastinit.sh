/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add east-any
ipsec whack --impair suppress_retransmits
echo initdone
