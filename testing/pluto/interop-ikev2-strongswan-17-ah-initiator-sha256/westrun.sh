strongswan up westnet-eastnet-ikev2
ping -n -c 4 -I 192.0.1.254 192.0.2.254
# cannot use ../../pluto/bin/ipsec-look.sh for strongswan
ip xfrm state
ip xfrm pol
echo done
