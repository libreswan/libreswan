# ROAD is down.  EAST, with autostart=keep which sets the UP bit, will
# schedule a revival event for NOW.  However, with revival impaired,
# won't actually schedule the event leaving the conn in revival-pending.
#
# While revival is pending, the kernel policy have transitioned to
# on-demand.

../../guestbin/wait-for.sh --match '#2: IMPAIR: revival: skip scheduling revival event' -- cat /tmp/pluto.log
../../guestbin/ipsec-kernel-policy.sh

# Now trigger the revival.  Since ROAD is down it will fail.  And
# being KEEP further revivals are abandoned.
ipsec whack --impair trigger-revival:2

# but road is really down, so that fails; and everything is deleted
../../guestbin/ipsec-kernel-policy.sh
