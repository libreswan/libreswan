# trigger OE and keep pinging until the tunnel is up
../../guestbin/fping-short.sh --lossy 5 -I 192.1.3.209 192.1.2.23
../../guestbin/ipsec-trafficstatus.sh --min 84
ipsec shuntstatus
echo done
