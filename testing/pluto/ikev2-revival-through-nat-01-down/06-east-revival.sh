# road is down, east with autostart=keep should try to revive; while
# this is happening kernel-policy should still be in place
../../guestbin/wait-for.sh --match 'supposed to remain up' -- cat /tmp/pluto.log
../../guestbin/ipsec-kernel-policy.sh

# Now trigger the revival.  Since ROAD is down it will fail.  And
# being KEEP further revivals are abandoned.
ipsec whack --impair trigger-revival:2

# since the NAT port is still open road should allow recovery
../../guestbin/wait-for.sh --match '^".*#4: initiator established Child SA using #3' -- cat /tmp/pluto.log
../../guestbin/ipsec-kernel-policy.sh
