ipsec whack --impair suppress-retransmits
ipsec auto --up west
../../pluto/bin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
sleep 50
../../pluto/bin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
grep reauthentication /tmp/pluto.log
echo done
