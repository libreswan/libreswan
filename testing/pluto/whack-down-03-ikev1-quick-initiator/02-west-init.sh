/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add west-to-east
ipsec whack --impair suppress_retransmits
ipsec whack --impair block_inbound:yes
echo "initdone"
