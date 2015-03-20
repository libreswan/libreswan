ipsec auto --up  westnet-eastnet-ipv4-psk-ikev2
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec look
# sleep for 60s to run a few liveness cycles 
sleep 60
kill -9 `cat /run/pluto/pluto.pid`
# sleep for timeout action
sleep 30
echo done
