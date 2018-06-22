ipsec auto --up westnet-eastnet-serpent
ping -n -c 4 -I 192.0.1.254 192.0.2.254
../../pluto/bin/ipsec-look.sh
echo done
