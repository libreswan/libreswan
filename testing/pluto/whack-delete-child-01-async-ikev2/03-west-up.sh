ipsec up west-cuckold
ipsec up west-cuckoo

../../guestbin/ping-once.sh --up 192.0.2.254
../../guestbin/ping-once.sh --up 192.0.20.254
ipsec trafficstatus

ipsec whack --delete-child --name west-cuckoo --async
ipsec whack --delete-child --name west-cuckold --async

../../guestbin/wait-for-pluto.sh '#2: connection is supposed to remain up'
../../guestbin/wait-for-pluto.sh '#3: connection is supposed to remain up'

../../guestbin/wait-for-pluto.sh '#4: initiator established'
../../guestbin/wait-for-pluto.sh '#5: initiator established'

../../guestbin/ping-once.sh --up 192.0.2.254
../../guestbin/ping-once.sh --up 192.0.20.254
ipsec trafficstatus
