ipsec up west-cuckold
ipsec up west-cuckoo

../../guestbin/ping-once.sh --up 192.0.2.254
../../guestbin/ping-once.sh --up 192.0.20.254
ipsec trafficstatus

# nhelpers=0 which should stop races
ipsec whack --rekey-child --name west-cuckoo --asynchronous
ipsec whack --rekey-child --name west-cuckold --asynchronous

../../guestbin/wait-for-pluto.sh '#4: initiator rekeyed'
../../guestbin/wait-for-pluto.sh '#5: initiator rekeyed'

../../guestbin/wait-for-pluto.sh '#2: ESP traffic information'
../../guestbin/wait-for-pluto.sh '#3: ESP traffic information'

../../guestbin/ping-once.sh --up 192.0.2.254
../../guestbin/ping-once.sh --up 192.0.20.254
ipsec trafficstatus
