hostname | grep nic > /dev/null || ipsec whack --trafficstatus
iptables -t nat -L -n
../../pluto/bin/ipsec-look.sh
: ==== cut ====
ipsec auto --status
: ==== tuc ====
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
