swanctl --initiate --child westnet-eastnet-ikev1 --loglevel 0
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
echo done
