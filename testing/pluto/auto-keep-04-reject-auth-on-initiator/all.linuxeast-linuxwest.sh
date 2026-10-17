#
# start pluto on east
#

east# /testing/guestbin/swan-prep --nokeys
east# /testing/x509/import.sh real/mainca/east.p12
east# /testing/x509/import.sh real/mainca/west.p12

east# ipsec start
east# ../../guestbin/wait-until-pluto-started

# Connection loaded via auto=keep.  Block revival, it shouldn't happen
# but just in case.

east# ipsec connectionstatus westnet-eastnet-ikev2 | grep keep
east# ipsec whack --impair revival

#
# Start pluto on west
#

west# /testing/guestbin/swan-prep --nokeys
west# # we only want/need to CAcert
west# /testing/x509/import.sh real/mainca/root.p12

west# ipsec whack --impair revival
west# ipsec start
west# ../../guestbin/wait-until-pluto-started
west# ipsec add westnet-eastnet-ikev2

#
# Try to bring up the connection; should fail and east should drop it
# on the floor.
#

west# ipsec up westnet-eastnet-ikev2

east# ../../guestbin/wait-for-pluto.sh --match '#1: received fatal error notification AUTHENTICATION_FAILED'
east# ../../guestbin/wait-for-pluto.sh --match '#1: encountered fatal error in state ESTABLISHED_IKE_SA'
east# grep '^[^|].*IMPAIR:' /tmp/pluto.log # should not match
