ipsec whack --impair ke-payload:omit
ipsec whack --impair revival  # give up after N retry attempts

# keyingtries=1, 3s
ipsec auto --up westnet-eastnet-k1
ipsec auto --delete westnet-eastnet-k1

# keyingtries=3, 9s
ipsec auto --up westnet-eastnet-k3
../../guestbin/wait-for.sh --match ' 3 of at most 3' -- cat /tmp/pluto.log
../../guestbin/wait-for.sh --match '"westnet-eastnet-k3".*skipping revival' -- cat /tmp/pluto.log
ipsec auto --delete westnet-eastnet-k3

# keyingtries=0 (default, forever)
ipsec auto --up westnet-eastnet
../../guestbin/wait-for.sh --match ' 3 of an unlimited number' -- cat /tmp/pluto.log

echo done
