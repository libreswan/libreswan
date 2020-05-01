ipsec auto --up westnet-eastnet-ipv4-psk-ikev2
../../pluto/bin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
# sleep for a bit to run a few liveness cycles
sleep 20
ipsec whack --impair send-no-delete
ipsec auto --delete westnet-eastnet-ipv4-psk-ikev2
ipsec auto --add westnet-eastnet-ipv4-psk-ikev2
# sleep for more than timeout action - 60 seconds
sleep 20
sleep 20
sleep 20
sleep 20
../../pluto/bin/ping-once.sh --down -I 192.0.1.254 192.0.2.254
echo done
