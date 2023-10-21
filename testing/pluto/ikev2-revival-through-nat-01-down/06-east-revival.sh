# road is down, east with autostart=keep should try to revive; while
# this is happening kernel-policy should still be in place
../../guestbin/wait-for.sh --match 'supposed to remain up' -- cat /tmp/pluto.log
../../guestbin/ipsec-kernel-policy.sh
# since the NAT port is still open road should allow recovery
../../guestbin/wait-for.sh --match '^".*#4: initiator established Child SA using #3' -- cat /tmp/pluto.log
../../guestbin/ipsec-kernel-policy.sh
