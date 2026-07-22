/testing/guestbin/swan-prep --46 --nokey

../../guestbin/ip.sh address show eth0 | grep global | sort

ipsec start
../../guestbin/wait-until-pluto-started

ipsec whack --impair revival

ipsec whack --impair omit_addke_notification:1

ipsec add west-cuckold
ipsec add west-cuckoo

echo "initdone"
