ipsec whack --trafficstatus
iptables -t nat -L -n
../../guestbin/ipsec-look.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
