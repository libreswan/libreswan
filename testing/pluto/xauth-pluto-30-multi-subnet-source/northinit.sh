/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
../../guestbin/block-non-ipsec.sh
ipsec auto --add north-pool
ipsec auto --add north-subnet1
ipsec auto --add north-subnet2
ipsec whack --trafficstatus
ipsec whack --impair suppress_retransmits
echo initdone
