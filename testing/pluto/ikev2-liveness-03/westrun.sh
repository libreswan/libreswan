ipsec auto --up  westnet-eastnet-ipv4-psk-ikev2
ping -n -c 4 -I 192.0.1.254 192.0.2.254
# sleep for 60s to run a few liveness cycles
sleep 30
sleep 30
ipsec whack --debug-all --impair-send-no-delete
ipsec auto --delete westnet-eastnet-ipv4-psk-ikev2
ipsec auto --add westnet-eastnet-ipv4-psk-ikev2
# sleep for timeout action
sleep 30
echo done
