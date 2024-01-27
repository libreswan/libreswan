ipsec auto --up westnet-eastnet
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus
# does not work on 3.29 for now leave it timer based rekey
ipsec whack --rekey-child --name westnet-eastnet
sleep 15
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
# only #3 should be there with traffic
ipsec trafficstatus
ipsec status | grep westnet-eastnet
# give time to strongswan to expire old one
sleep 53
