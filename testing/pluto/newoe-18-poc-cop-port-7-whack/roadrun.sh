ipsec whack --oppohere 192.1.3.209 --oppothere 192.1.2.23 --oppoproto 6 --oppodport 7

# should show tunnel and no shunts, and zero traffic count
ipsec trafficstatus
ipsec shuntstatus

# generate some traffic to be encrypted
echo TRIGGER-OE | socat - TCP:192.1.2.23:7,bind=192.1.3.209

# show non-zero counters
ipsec trafficstatus | sed -e 's/Bytes=[1-9][0-9]*,/Bytes=NNN,/g'

echo done
