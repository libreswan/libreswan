# nic nicinit.sh

nic# iptables -t nat -F
nic# iptables -F
nic# # NAT
nic# iptables -t nat -A POSTROUTING --source 192.1.3.209/32 --destination 0.0.0.0/0 -j SNAT -p udp --to-source 192.1.2.254:33000-33100
nic# iptables -t nat -A POSTROUTING --source 192.1.3.210/32 --destination 0.0.0.0/0 -j SNAT -p udp --to-source 192.1.2.254:34000-34100
nic# # make sure that we never acidentially let ESP through.
nic# #
nic# iptables -I FORWARD 1 --proto 50 -j DROP
nic# iptables -I FORWARD 2 --destination 192.0.2.0/24 -j DROP
nic# iptables -I FORWARD 3 --source 192.0.2.0/24 -j DROP
nic# # route
nic# iptables -I INPUT 1 --destination 192.0.2.0/24 -j DROP
nic# # Display the table, so we know it is correct.
nic# iptables -t nat -L -n
nic# iptables -L -n
nic# echo "initdone"
nic# : ==== end ====

# east eastinit.sh

east# /testing/guestbin/swan-prep --nokeys
east# /testing/x509/import.sh real/mainca/east.p12
east# /testing/x509/import.sh real/mainca/road.end.cert

east# ipsec start
east# ../../guestbin/wait-until-pluto-started
east# ipsec add roadnet-eastnet-ipv4-psk-ikev1
east# echo "initdone"

# road roadinit.sh

road# /testing/guestbin/swan-prep --nokeys
road# /testing/x509/import.sh real/mainca/road.p12
road# /testing/x509/import.sh real/mainca/east.end.cert

road# ipsec start
road# ../../guestbin/wait-until-pluto-started
road# ipsec add westnet-eastnet-ipv4-psk-ikev1
road# echo "initdone"

# road roadrun.sh

road# ipsec whack --xauthname 'use3' --xauthpass 'use1pass' --name westnet-eastnet-ipv4-psk-ikev1 --initiate
road# ../../guestbin/ping-once.sh --up -I 192.0.2.1 192.1.2.23

east# ../../guestbin/wait-for-pluto.sh --match '#2: IPsec SA established tunnel mode'

road# ipsec trafficstatus

# change ip, emulating sudden switching network

road# ipsec whack --impair send_no_delete
road# ipsec stop

road# ifconfig eth0 192.1.3.210 netmask 255.255.255.0
road# route add default gw 192.1.3.254
road# ipsec start
road# ../../guestbin/wait-until-pluto-started
road# ipsec add westnet-eastnet-ipv4-psk-ikev1

road# ipsec whack --xauthname 'use3' --xauthpass 'use1pass' --name westnet-eastnet-ipv4-psk-ikev1 --initiate

east# ../../guestbin/wait-for-pluto.sh --match '#4: IPsec SA established tunnel mode'

road# ../../guestbin/ping-once.sh --up -I 192.0.2.1 192.1.2.23
road# ipsec trafficstatus

# final final.sh

final# ipsec connectionstatus westnet-eastnet-ipv4-psk-ikev1
final# ipsec trafficstatus
final# # should show no hits
final# grep INVALID_IKE_SPI /tmp/pluto.log
final# grep MSG_TRUNC /tmp/pluto.log
final# grep "cannot route" /tmp/pluto.log
