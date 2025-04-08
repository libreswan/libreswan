# road is down, east with autostart=keep should try to revive; while
# this is happening kernel-policy should still be in place
../../guestbin/wait-for-pluto.sh 'supposed to remain up'
ipsec _kernel policy

# Now trigger the revival.  Since ROAD is down it will fail.  And
# being KEEP further revivals are abandoned.
ipsec whack --impair trigger_revival:2

# since the NAT port is still open road should allow recovery
../../guestbin/wait-for-pluto.sh '^".*#4: initiator established Child SA using #3'
ipsec _kernel policy
