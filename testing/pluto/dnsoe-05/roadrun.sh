# Should succeed if it can check all pubkeys received via DNS
ipsec whack --oppohere 192.1.3.209 --oppothere 192.1.2.66
grep "DNS QUESTION" /tmp/pluto.log
# should show large set of keys in pluto cache from IPSECKEY records
ipsec whack --listpubkeys
# should show established tunnel and no bare shunts
# ping should succeed through tunnel
ping -n -c 2 -I 192.1.3.209 192.1.2.66
ipsec whack --trafficstatus
ipsec whack --shuntstatus
ipsec whack --trafficstatus
echo done
