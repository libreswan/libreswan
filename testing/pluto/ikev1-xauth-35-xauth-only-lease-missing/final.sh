# On EAST, expect to see the peer proposing EAST and WEST as the child
# selectors.  Hence it is rejected.

grep '#1: the peer proposed' /tmp/pluto.log
grep '#1: sending encrypted notification' /tmp/pluto.log
