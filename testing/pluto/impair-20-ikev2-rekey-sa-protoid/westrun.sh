ipsec whack --impair revival

# bring up west and then immediately re-key
ipsec up west # sanitize-retransmits
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus
ipsec whack --rekey-child --name west --async
../../guestbin/wait-for-pluto.sh '^".*#3: initiator rekeyed Child SA #2'
../../guestbin/wait-for-pluto.sh '^".*#2: ESP traffic information:'
ipsec down west # sanitize-retransmits

# protoid=none
ipsec up west # sanitize-retransmits
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus
ipsec whack --impair v2n_rekey_sa_protoid:0 --impair emitting
ipsec whack --rekey-child --name west --async
../../guestbin/wait-for-pluto.sh '^".*#6: CREATE_CHILD_SA failed'
ipsec down west # sanitize-retransmits

# protoid=IKE
ipsec up west # sanitize-retransmits
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus
ipsec whack --impair v2n_rekey_sa_protoid:1 --impair emitting
ipsec whack --rekey-child --name west --async
../../guestbin/wait-for-pluto.sh '^".*#9: CREATE_CHILD_SA failed'
ipsec down west # sanitize-retransmits

# protoid=unknown
ipsec up west # sanitize-retransmits
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus
ipsec whack --impair v2n_rekey_sa_protoid:4 --impair emitting
ipsec whack --rekey-child --name west --async
../../guestbin/wait-for-pluto.sh '^".*#12: CREATE_CHILD_SA failed'
ipsec down west # sanitize-retransmits
