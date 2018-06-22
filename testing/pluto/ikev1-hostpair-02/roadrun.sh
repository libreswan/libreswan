ipsec whack --xauthname 'use3' --xauthpass 'use1pass' --initiate --name westnet-eastnet-ipv4-psk-ikev1
ping -n -c 2 -I 192.0.2.1 192.1.2.23
ipsec whack --trafficstatus
# create havoc
ipsec whack --impair send-no-delete
ipsec auto --add westnet-eastnet-ipv4-psk-ikev1
ipsec whack --xauthname 'use3' --xauthpass 'use1pass' --initiate --name westnet-eastnet-ipv4-psk-ikev1
ipsec auto --add westnet-eastnet-ipv4-psk-ikev1
ipsec whack --xauthname 'use3' --xauthpass 'use1pass' --initiate --name westnet-eastnet-ipv4-psk-ikev1
ipsec auto --add westnet-eastnet-ipv4-psk-ikev1
ipsec whack --xauthname 'use3' --xauthpass 'use1pass' --initiate --name westnet-eastnet-ipv4-psk-ikev1
ping -n -c 4 -I 192.0.2.1 192.1.2.23
ipsec whack --trafficstatus
echo done
