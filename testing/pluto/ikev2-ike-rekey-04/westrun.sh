ipsec auto --up westnet-eastnet-ikev2a
ipsec auto --up westnet-eastnet-ikev2b
ipsec auto --up westnet-eastnet-ikev2c
# expect: ike #1 IPsec #2 #3 #4
ipsec status |grep STATE_
sleep 30
# ipsec should be rekeyed
# expect: ike #1 IPsec #5 #6 #7
ipsec status |grep STATE_
sleep 20
# ike sa should be rekeyed
# expect: ike #8 IPsec #9 #10 #11
ipsec status |grep STATE_
sleep 30
# second rekey of IPsec SAs
# expect: ike #8 IPsec #12 #13 #14
ipsec status |grep STATE_
echo done
