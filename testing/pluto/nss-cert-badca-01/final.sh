# Error only expected to show up on east
grep ERROR /tmp/pluto.log | grep -v NLMSG_ERROR
