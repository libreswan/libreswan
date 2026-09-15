swanctl --initiate --child westnet-eastnet-ikev2 --loglevel 0
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254

swanctl --rekey --ike westnet-eastnet-ikev2
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254

swanctl --rekey --ike westnet-eastnet-ikev2
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254

swanctl --terminate --ike westnet-eastnet-ikev2 --loglevel 0
echo done
