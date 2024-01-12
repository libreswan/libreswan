ipsec whack --impair drop_xauth_r0
# connection will fail to establish
ipsec whack --xauthname 'use3' --xauthpass 'use1pass' --name road-east --initiate
ipsec whack --trafficstatus
echo done
