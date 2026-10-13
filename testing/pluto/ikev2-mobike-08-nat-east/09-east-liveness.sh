../../guestbin/wait-for-pluto.sh --match 'MOBIKE mapping change: updated remote to'
ipsec _kernel state | grep "dport 5[0-9][0-9][0-9][0-9]"
ipsec trafficstatus
../../guestbin/xfrmcheck.sh
