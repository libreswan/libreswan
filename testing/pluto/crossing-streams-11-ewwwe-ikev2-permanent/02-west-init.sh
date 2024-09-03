/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair revival
ipsec whack --impair suppress_retransmits
ipsec whack --impair block_inbound:yes
ipsec auto --add east-west
