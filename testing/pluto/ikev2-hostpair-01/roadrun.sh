ipsec auto --up westnet-eastnet-ipv4-psk-ikev2
../../guestbin/ping-once.sh --up -I 192.0.2.1 192.1.2.23
ipsec whack --trafficstatus
# change ip, emulating sudden switching network
ipsec whack --impair send-no-delete
ipsec stop
ifconfig eth0 192.1.3.210 netmask 255.255.255.0
route add default gw 192.1.3.254
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress-retransmits
ipsec auto --add westnet-eastnet-ipv4-psk-ikev2
ipsec auto --up westnet-eastnet-ipv4-psk-ikev2
# should not fail to ping
../../guestbin/ping-once.sh --up -I 192.0.2.1 192.1.2.23
ipsec whack --trafficstatus
echo done
