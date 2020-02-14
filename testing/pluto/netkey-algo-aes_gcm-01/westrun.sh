ipsec auto --up westnet-eastnet-gcm
../../pluto/bin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
../../pluto/bin/ipsec-look.sh
echo done
