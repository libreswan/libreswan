# Expected to fail as all IPSECKEY's are wrong
ipsec whack --oppohere 192.1.3.209 --oppothere 192.1.2.67
grep "DNS QUESTION" /tmp/pluto.log
# should show large set of keys in pluto cache from IPSECKEY records
ipsec whack --listpubkeys
echo done
