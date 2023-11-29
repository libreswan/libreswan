#sleep a bit east is bring up the tunnel
sleep 5
# the tunnel should be up now
strongswan status
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
echo "sleep 25 sec to ike to rekey "
sleep 25
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
sleep 5
strongswan status
echo "sleep 30 sec to ike to rekey "
sleep 30
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
sleep 5
strongswan status
echo done
