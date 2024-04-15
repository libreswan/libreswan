/testing/guestbin/swan-prep --4 --nokey

ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
ipsec auto --add east-west
