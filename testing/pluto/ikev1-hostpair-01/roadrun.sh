ipsec whack --xauthname 'use3' --xauthpass 'use1pass' --name westnet-eastnet-ipv4-psk-ikev1 --initiate
../../guestbin/ping-once.sh --up -I 192.0.2.1 192.1.2.23
ipsec whack --trafficstatus
# change ip, emulating sudden switching network
ipsec whack --impair send-no-delete
ipsec stop
ifconfig eth0 192.1.3.210 netmask 255.255.255.0
route add default gw 192.1.3.254
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ipv4-psk-ikev1
ipsec whack --xauthname 'use3' --xauthpass 'use1pass' --name westnet-eastnet-ipv4-psk-ikev1 --initiate
# should not fail to ping
../../guestbin/ping-once.sh --up -I 192.0.2.1 192.1.2.23
ipsec whack --trafficstatus
echo done
