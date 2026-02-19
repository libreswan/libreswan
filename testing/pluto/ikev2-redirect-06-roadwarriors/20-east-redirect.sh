# both clients should be connected now
ipsec whack --trafficstatus
# send REDIRECT in informational to all tunnels from connection east-any (north and road)
ipsec whack --name '"east-any"[1]' --redirect-to 192.1.2.45
ipsec whack --name '$3' --redirect-to 192.1.2.45
ipsec whack --name east-any --redirect-to 192.1.2.45
# give them time to be redirected
../../guestbin/wait-for.sh --no-match east-any -- ipsec trafficstatus
