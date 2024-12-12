../../guestbin/swan-prep --x509
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add any-east
ipsec whack --impair suppress_retransmits
echo initdone
