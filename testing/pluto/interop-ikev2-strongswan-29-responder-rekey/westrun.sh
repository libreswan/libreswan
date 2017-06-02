#sleep a bit east is bring up the tunnel
sleep 5
# the tunnel should be up now
strongswan status
ping -n -c 4 -I 192.0.1.254 192.0.2.254
echo "sleep 25 sec to ike to rekey "
sleep 25
ping -n -c 4 -I 192.0.1.254 192.0.2.254
strongswan status
echo "sleep 30 sec to ike to rekey "
sleep 30
ping -n -c 4 -I 192.0.1.254 192.0.2.254
strongswan status
echo done
