/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
ipsec auto --add road-eastnet-encapsulation=yes
ipsec status | grep encapsulation:
echo "initdone"
