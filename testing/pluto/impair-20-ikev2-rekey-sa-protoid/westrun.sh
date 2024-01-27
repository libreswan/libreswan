ipsec whack --impair revival

# bring up west and then immediately re-key
ipsec auto --up west
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
ipsec whack --rekey-child --name west --async
../../guestbin/wait-for-pluto.sh '^".*#3: initiator rekeyed Child SA #2'
../../guestbin/wait-for-pluto.sh '^".*#2: ESP traffic information:'
ipsec auto --down west

# protoid=none
ipsec auto --up west
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
ipsec whack --impair v2n_rekey_sa_protoid:0 --impair emitting
ipsec whack --rekey-child --name west --async
../../guestbin/wait-for-pluto.sh '^".*#6: CREATE_CHILD_SA failed'
ipsec auto --down west

# protoid=IKE
ipsec auto --up west
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
ipsec whack --impair v2n_rekey_sa_protoid:1 --impair emitting
ipsec whack --rekey-child --name west --async
../../guestbin/wait-for-pluto.sh '^".*#9: CREATE_CHILD_SA failed'
ipsec auto --down west

# protoid=unknown
ipsec auto --up west
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
ipsec whack --impair v2n_rekey_sa_protoid:4 --impair emitting
ipsec whack --rekey-child --name west --async
../../guestbin/wait-for-pluto.sh '^".*#12: CREATE_CHILD_SA failed'
ipsec auto --down west
