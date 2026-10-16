# this would fail to establish
ipsec up --asynchronous road-east-ikev2
../../guestbin/wait-for.sh --match 'deleting IKE SA' -- grep '^"road-east-ikev2" #1: deleting IKE SA' /tmp/pluto.log > /dev/null
grep -E '^"road-east-ikev2" #1: (IKEv2 DNS query|fetching IDr|deleting IKE SA)' /tmp/pluto.log
echo done
