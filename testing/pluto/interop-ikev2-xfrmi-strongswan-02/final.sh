ip -s link show ipsec0
ip rule show
ip route
ip route show table 220
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
