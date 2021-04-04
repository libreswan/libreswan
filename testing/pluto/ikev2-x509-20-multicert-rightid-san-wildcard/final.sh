# we should see conn other being up
ipsec whack --trafficstatus
# On east, we should see it has switched
hostname | grep east > /dev/null && grep '^[^|].* switched ' /tmp/pluto.log
ipsec whack --shutdown
: ==== cut ====
ipsec auto --status
: ==== tuc ====
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
