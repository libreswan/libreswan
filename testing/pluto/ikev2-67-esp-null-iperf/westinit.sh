/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --impair allow-null-none
# normally NONE is not emitted
ipsec whack --impair v2-proposal-integ:allow-none
ipsec whack --impair suppress-retransmits
ipsec auto --add west-east
echo "initdone"
