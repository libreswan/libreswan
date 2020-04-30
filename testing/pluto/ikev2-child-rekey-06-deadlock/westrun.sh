ipsec auto --status | grep west
ipsec auto --up west
# ../../pluto/bin/ping-once.sh ...?
taskset 0x3 ping -w 3 -n -c 2 192.1.2.23
ipsec trafficstatus
# this rekey, 1 #3, should succeed
ipsec whack --rekey-ipsec --name west
sleep 15
# this rekey, 2 #4, should fail creating an unacknowledged message and dead lock
ipsec whack --rekey-ipsec --name west
# this rekey, 3 #5, message will not be sent, #1.#5
ipsec whack --rekey-ipsec --name west
# there should be one hit
grep "next initiator blocked by outstanding" OUTPUT/west.pluto.log | sed -e 's/\(.*\ |\)//' | sort -u
ipsec status | grep STATE_
echo done
