# bring up west and confirm; expect IKE #1 CHILD #2
ipsec up west # sanitize-retransmits
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus
ipsec showstates

# rekey CHILD SA; expect IKE #1 CHILD #3
ipsec whack --rekey-child --name west
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus
ipsec showstates

# rekey CHILD SA; expect IKE #1 CHILD #4
ipsec whack --rekey-child --name west
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus
ipsec showstates

echo done
