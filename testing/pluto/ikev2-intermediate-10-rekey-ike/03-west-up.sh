ipsec up west-cuckold
ipsec up west-cuckoo

ipsec whack --rekey-ike --name west-cuckold
../../guestbin/wait-for-pluto.sh '#4: initiator rekeyed IKE SA #1'

ipsec whack --rekey-ike --name west-cuckold
../../guestbin/wait-for-pluto.sh '#5: initiator rekeyed IKE SA #4'

../../guestbin/ping-once.sh --up 192.0.2.254
../../guestbin/ping-once.sh --up 192.0.20.254
ipsec trafficstatus
