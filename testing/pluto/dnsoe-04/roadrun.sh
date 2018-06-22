# two preloaded keys are wrong and not used, dns lookup finds real key
ipsec whack --oppohere 192.1.3.209 --oppothere 192.1.2.23
ping -n -c 2 -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus
# this should show DNS query
grep "DNS QUESTION" /tmp/pluto.log
# shows existing bad keys replaced with working new key (why is that?)
ipsec whack --listpubkeys
echo done
