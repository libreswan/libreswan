../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh
ipsec auto --status
if [ -f  /var/run/pluto/pluto.pid ]; then kill `cat /var/run/pluto/pluto.pid` ; fi
sleep 2
ps -ax | grep pluto
