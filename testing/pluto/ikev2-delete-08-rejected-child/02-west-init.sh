/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add rejected-child
ipsec whack --impair revival
echo initdone
