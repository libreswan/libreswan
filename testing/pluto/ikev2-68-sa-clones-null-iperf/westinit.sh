/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --impair allow-null-none
ipsec whack --impair no-ikev2-exclude-integ-none,ikev2-include-integ-none
ipsec whack --impair suppress-retransmits
ipsec auto --add west-east
echo "initdone"
