ipsec auto --up westnet-eastnet
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec trafficstatus 
# does not work on 3.29 for now leave it timer based rekey
ipsec whack --rekey-ipsec --name westnet-eastnet
sleep 25
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec trafficstatus 
ipsec status | grep westnet-eastnet
