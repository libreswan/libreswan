if [ -f /var/run/charon.pid ]; then strongswan status ; fi
: ==== cut ====
if [ -f /var/run/pluto/pluto.pid ]; then ipsec look ; fi # ../../pluto/bin/ipsec-look.sh
if [ -f /var/run/pluto/pluto.pid ]; then ipsec auto --status ; fi
if [ -f /var/run/charon.pid ]; then strongswan statusall ; fi
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
