ipsec auto --up west

: ==== cut ====
ip -s xfrm state
: ==== tuc ====

# find out the actual number of packets
actual=$(sed -n -e 's/.* ipsec-max-bytes.* actual-limit=\([0-9]*\).*/\1/ p' /tmp/pluto.log | head -1)
echo $actual

pings() { local n=0 ; while test $n -lt $1 ; do  n=$((n + 1)) ; ../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254 ; done ; }
pingover() { while ipsec trafficstatus | grep -e "$1" ; do ../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254 ; sleep 5 ; done ; }

pings $((actual / 84))
pingover '#2'

pings $((actual / 84))
pingover '#3'

pings $((actual / 84))
pingover '#4'
