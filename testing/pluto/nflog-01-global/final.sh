../../pluto/bin/ipsec-look.sh
: ==== cut ====
ipsec auto --status
: ==== tuc ====
ipsec stop
# show no nflog left behind
iptables -L -n
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
