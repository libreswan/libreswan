ipsec whack --impair suppress-retransmits
ipsec auto --up  west
ping -n -c 2 -I 192.0.1.254 192.0.2.254
sleep 50
ping -n -c 2 -I 192.0.1.254 192.0.2.254
grep reauthentication /tmp/pluto.log
echo done
