/testing/guestbin/swan-prep --46 --nokey

ip addr show eth0 | grep global | sort

ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
ipsec add west-cuckold
ipsec add west-cuckoo

echo "initdone"
