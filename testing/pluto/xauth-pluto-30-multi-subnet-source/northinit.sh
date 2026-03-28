/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
../../guestbin/block-non-ipsec.sh
ipsec add north-pool
ipsec add north-subnet1
ipsec add north-subnet2
ipsec trafficstatus
ipsec whack --impair suppress_retransmits
echo initdone
