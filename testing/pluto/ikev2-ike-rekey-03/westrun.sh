# REKEY times are approx - allow for lag
# bring up #1 rekey at 53; #2; rekey at 23, 46, 69, ...
ipsec auto --up westnet-eastnet-ikev2a
# bring up #3; rekey at 23, 46, 69, ...
ipsec auto --up westnet-eastnet-ikev2b
# bring up #4; rekey at 23, 46, 69, ...
ipsec auto --up westnet-eastnet-ikev2c
# confirm #2-#4 up
../../pluto/bin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
../../pluto/bin/ping-once.sh --up -I 192.0.100.254 192.0.200.254
../../pluto/bin/ping-once.sh --up -I 192.0.101.254 192.0.201.254
ipsec whack --trafficstatus
ipsec status |grep STATE_
# Wait intil 30(23+10) - between 23 and 46
sleep 23
sleep 7
# confirm #2-#4 replaced by #5-#7
../../pluto/bin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
../../pluto/bin/ping-once.sh --up -I 192.0.100.254 192.0.200.254
../../pluto/bin/ping-once.sh --up -I 192.0.101.254 192.0.201.254
ipsec whack --trafficstatus
ipsec status |grep STATE_|sort
# Wait intil 60(30+30) - between 46 and 69, after 53
sleep 30
# confirm #5-#7 replaced by #8-#10; and #1 by #11
../../pluto/bin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
../../pluto/bin/ping-once.sh --up -I 192.0.100.254 192.0.200.254
../../pluto/bin/ping-once.sh --up -I 192.0.101.254 192.0.201.254
# in final.sh
# ipsec whack --trafficstatus
# ipsec status |grep STATE_
echo done
