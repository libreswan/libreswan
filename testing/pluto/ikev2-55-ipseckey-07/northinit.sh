/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add north-east
ipsec whack --impair suppress-retransmits
# road should have only one public key of its own
ipsec auto --listpubkeys
echo "initdone"
