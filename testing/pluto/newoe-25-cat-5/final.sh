ipsec whack --trafficstatus
iptables -t nat -L -n
../../pluto/bin/ipsec-look.sh | sed "s/udp sport [0-9]* /udp sport XXXXX /"
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
