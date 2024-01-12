# create havoc
ipsec whack --impair send_no_delete
# #3.#4
ipsec auto --add westnet-eastnet-ipv4-psk-ikev1
ipsec whack --xauthname 'use3' --xauthpass 'use1pass' --initiate --name westnet-eastnet-ipv4-psk-ikev1
# #5.#6
ipsec auto --add westnet-eastnet-ipv4-psk-ikev1
ipsec whack --xauthname 'use3' --xauthpass 'use1pass' --initiate --name westnet-eastnet-ipv4-psk-ikev1
# #7.#8
ipsec auto --add westnet-eastnet-ipv4-psk-ikev1
ipsec whack --xauthname 'use3' --xauthpass 'use1pass' --initiate --name westnet-eastnet-ipv4-psk-ikev1
