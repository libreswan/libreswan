../../guestbin/ipsec-look.sh
ipsec auto --status
if [ -f  /var/run/pluto/pluto.pid ]; then kill `cat /var/run/pluto/pluto.pid` ; fi
sleep 2
ps -ax | grep pluto
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
