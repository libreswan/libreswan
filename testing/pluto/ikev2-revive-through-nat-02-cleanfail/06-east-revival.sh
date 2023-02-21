# road is down, east with autostart=keep should try to revive; while
# this is happening kernel-policy should still be in place
../../guestbin/wait-for.sh --match 'deleting IKE SA but connection is supposed to remain up' -- cat /tmp/pluto.log
../../guestbin/ipsec-kernel-policy.sh
# but road is really down, so that fails; and everything is deleted
../../guestbin/wait-for.sh --match '5 second timeout exceeded after 4 retransmits' -- cat /tmp/pluto.log
../../guestbin/ipsec-kernel-policy.sh
