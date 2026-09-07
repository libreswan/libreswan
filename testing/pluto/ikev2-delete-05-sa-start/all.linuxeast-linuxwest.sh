# start west first so it is ready for east; reduces odds of east
# timing out

west# /testing/guestbin/swan-prep --hostkeys
west# ipsec start
west# ../../guestbin/wait-until-pluto-started
west# echo "initdone"

# start east; since it has auto=start it will immediately initiate to
# west; wait for it to establish

east# /testing/guestbin/swan-prep --hostkeys
east# ipsec start
east# ../../guestbin/wait-until-pluto-started
east# # connection is loaded and initiated via auto=start
east# ../../guestbin/wait-for-pluto.sh --match '#2: initiator established Child SA using #1'

# confirm traffic is flowing west->east

west# ../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
west# ipsec trafficstatus

# sending delete/notify; since east has auto=start it should
# re-establish

west# ipsec down westnet-eastnet-auto
east# ../../guestbin/wait-for-pluto.sh --match '#4: initiator established Child SA using #3'

# now confirm the new SA is up with traffic flowing

west# ../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
west# ipsec trafficstatus
