ipsec auto --up westnet-eastnet
ping -w 4 -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec trafficstatus 
# does not work on 3.29 for now leave it timer based rekey
ipsec whack --rekey-ipsec --name westnet-eastnet
sleep 15
ping -w 4 -n -c 4 -I 192.0.1.254 192.0.2.254
# only #3 should be there with traffic
ipsec trafficstatus 
ipsec status | grep westnet-eastnet
# give time to strongswan to expire old one
sleep 53
