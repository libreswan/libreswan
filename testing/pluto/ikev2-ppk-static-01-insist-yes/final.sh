# confirm PPK was used
grep "PPK AUTH calculated" /tmp/pluto.log
ipsec whack --shutdown
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
