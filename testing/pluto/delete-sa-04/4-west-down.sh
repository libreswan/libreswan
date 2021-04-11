# east is within the last 60s of IPsec SA lifetime
sleep 5
ipsec auto --down west-east-auto
sleep 5
# east should have brought up tunnel again
ipsec trafficstatus
# confirm traffic flow over proper IPsec SA
ping -n -q -c 4 -I 192.1.2.45 192.1.2.23
