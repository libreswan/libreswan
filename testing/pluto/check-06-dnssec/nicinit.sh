iptables -t nat -F
iptables -F
/bin/time -o OUTPUT/$(hostname).time /testing/guestbin/nic-dnssec.sh start
echo done
