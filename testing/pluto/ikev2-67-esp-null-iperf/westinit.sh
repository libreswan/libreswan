/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair allow_null_none
# normally NONE is not emitted
ipsec whack --impair v2_proposal_integ:allow-none
ipsec whack --impair suppress_retransmits
ipsec auto --add west-east
echo "initdone"
