# see description.txt
ipsec auto --add west-ckaid-rawkey
ipsec auto --up west-ckaid-rawkey
../../pluto/bin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
