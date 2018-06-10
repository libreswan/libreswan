../../pluto/bin/ipsec-look.sh
ipsec auto --status
if [ -f  /var/run/pluto/pluto.pid ]; then kill `cat /var/run/pluto/pluto.pid` ; fi
sleep 2
ps -ax | grep pluto
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
