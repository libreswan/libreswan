# we should see a connection switch on east
ipsec whack --trafficstatus
hostname | grep east && grep '^[^|].* switched ' /tmp/pluto.log
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
