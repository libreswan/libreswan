# IKE #1 Child #3
ipsec auto --up westnet-eastnet-ikev2a
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
# Child #3
ipsec auto --up westnet-eastnet-ikev2b
../../guestbin/ping-once.sh --up -I 192.0.100.254 192.0.200.254
# Child #4
ipsec auto --up westnet-eastnet-ikev2c
../../guestbin/ping-once.sh --up -I 192.0.101.254 192.0.201.254
# expect Child #2 #3 #4
ipsec whack --trafficstatus

# rekey to Child #5 #6 #7
../../guestbin/wait-for-pluto.sh '^".*#5: initiator rekeyed Child SA'
../../guestbin/wait-for-pluto.sh '^".*#6: initiator rekeyed Child SA'
../../guestbin/wait-for-pluto.sh '^".*#7: initiator rekeyed Child SA'
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
../../guestbin/ping-once.sh --up -I 192.0.100.254 192.0.200.254
../../guestbin/ping-once.sh --up -I 192.0.101.254 192.0.201.254
# wait for old, so that they are not in traffic status
../../guestbin/wait-for-pluto.sh '^".*#2: ESP traffic information:'
../../guestbin/wait-for-pluto.sh '^".*#3: ESP traffic information:'
../../guestbin/wait-for-pluto.sh '^".*#4: ESP traffic information:'
# expect Child #5 #6 #7
ipsec whack --trafficstatus

# rekey to Child #8 #9 #10
../../guestbin/wait-for-pluto.sh '^".*#8: initiator rekeyed Child SA'
../../guestbin/wait-for-pluto.sh '^".*#9: initiator rekeyed Child SA'
../../guestbin/wait-for-pluto.sh '^".*#10: initiator rekeyed Child SA'
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
../../guestbin/ping-once.sh --up -I 192.0.100.254 192.0.200.254
../../guestbin/ping-once.sh --up -I 192.0.101.254 192.0.201.254
# wait for old, so that they are not in traffic status
../../guestbin/wait-for-pluto.sh '^".*#5: ESP traffic information:'
../../guestbin/wait-for-pluto.sh '^".*#6: ESP traffic information:'
../../guestbin/wait-for-pluto.sh '^".*#7: ESP traffic information:'
# expect Child #8 #9 #10
ipsec whack --trafficstatus

echo done
