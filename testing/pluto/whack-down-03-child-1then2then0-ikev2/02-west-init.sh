/testing/guestbin/swan-prep --46 --nokey

../../guestbin/ip.sh address show eth0 | grep global | sort

ipsec start
../../guestbin/wait-until-pluto-started

ipsec whack --impair revival

ipsec add west-cuckold
ipsec add west-cuckoo-1
ipsec add west-cuckoo-2

echo "initdone"
