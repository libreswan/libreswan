../../guestbin/ipsec-look.sh
ipsec stop
# show no nflog left behind
iptables -L -n
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
