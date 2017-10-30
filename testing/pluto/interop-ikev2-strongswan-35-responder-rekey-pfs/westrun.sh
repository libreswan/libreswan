#sleep 15 seconds,  east is bring up the tunnel
sleep 15
strongswan status
ping -n -s 80 -c  8 -I 192.0.1.254 192.0.2.254
# this suhould have something like westnet-eastnet-ikev2{3} and no packet loss.
strongswan status
echo done
