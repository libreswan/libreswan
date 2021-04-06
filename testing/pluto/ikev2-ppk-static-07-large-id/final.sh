# confirm PPK was used
grep "PPK AUTH calculated" /tmp/pluto.log
ipsec whack --shutdown
