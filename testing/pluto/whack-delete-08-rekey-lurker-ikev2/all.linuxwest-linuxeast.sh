#
# east eastinit.sh
#

east# /testing/guestbin/swan-prep --nokey
east# ipsec start
east# ../../guestbin/wait-until-pluto-started
east# ipsec add east

#
# west westinit.sh
#

west# /testing/guestbin/swan-prep --nokey
west# ipsec pluto --efence-protect --config /etc/ipsec.conf
west# ../../guestbin/wait-until-pluto-started
west# ipsec add west
west# ipsec whack --impair revival

#
# Bring up connection
#

west# ipsec up west # sanitize-retransmits
west# ../../guestbin/ping-once.sh --up 192.0.2.254
west# ipsec trafficstatus

# rekey flipping order
west# ipsec whack --rekey-ike --name west

#
# Restart on east
#

east# ipsec whack --impair send_no_delete
east# ipsec stop

east# ipsec start
east# ../../guestbin/wait-until-pluto-started

east# ipsec add east
east# ipsec up east

#
# Delete west
#

west# ipsec delete west

