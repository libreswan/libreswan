/testing/guestbin/swan-prep
../../guestbin/ip.sh route
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
echo "initdone"
