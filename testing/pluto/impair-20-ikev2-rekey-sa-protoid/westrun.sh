ipsec whack --impair revival

# bring up west and then immediately re-key
ipsec auto --up west
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
ipsec whack --rekey-ipsec --name west --async
../../guestbin/wait-for.sh --match '^".*#3: initiator rekeyed Child SA #2' -- cat /tmp/pluto.log
../../guestbin/wait-for.sh --match '^".*#2: ESP traffic information:' -- cat /tmp/pluto.log
ipsec auto --down west

# protoid=none
ipsec auto --up west
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
ipsec whack --impair v2n_rekey_sa_protoid:0 --impair emitting
ipsec whack --rekey-ipsec --name west --async
../../guestbin/wait-for.sh --match '^".*#6: CREATE_CHILD_SA failed' -- cat /tmp/pluto.log
ipsec auto --down west

# protoid=IKE
ipsec auto --up west
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
ipsec whack --impair v2n_rekey_sa_protoid:1 --impair emitting
ipsec whack --rekey-ipsec --name west --async
../../guestbin/wait-for.sh --match '^".*#9: CREATE_CHILD_SA failed' -- cat /tmp/pluto.log
ipsec auto --down west

# protoid=unknown
ipsec auto --up west
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
ipsec whack --impair v2n_rekey_sa_protoid:4 --impair emitting
ipsec whack --rekey-ipsec --name west --async
../../guestbin/wait-for.sh --match '^".*#12: CREATE_CHILD_SA failed' -- cat /tmp/pluto.log
ipsec auto --down west
