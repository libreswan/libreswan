/testing/guestbin/swan-prep --46 --nokey

../../guestbin/ip.sh address show eth0 | grep global | sort

ipsec start
../../guestbin/wait-until-pluto-started

ipsec whack --impair revival

ipsec add west-cuckoo
ipsec add west-cuckold

echo "initdone"
ipsec whack --impair revival
