/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair revival
ipsec whack --impair suppress-retransmits
ipsec auto --add east-west
