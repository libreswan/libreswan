hostname | grep east > /dev/null && ipsec whack --trafficstatus
: ==== cut ====
ipsec status
hostname | grep east > /dev/null && ipsec auto --delete east-any
: ==== tuc ====
hostname | grep east > /dev/null && ipsec stop
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
