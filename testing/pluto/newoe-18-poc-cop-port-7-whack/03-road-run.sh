ipsec whack --oppohere 192.1.3.209 --oppothere 192.1.2.23 --oppoproto 6 --oppodport 7
# should show tunnel and no shunts, and zero traffic count
ipsec whack --trafficstatus
ipsec whack --shuntstatus
# generate some traffic to be encrypted
echo TRIGGER-OE | socat - TCP:192.1.2.23:7,bind=192.1.3.209
# show non-zero counters
# workaround for diff err msg between fedora versions resulting in diff byte count
ipsec whack --trafficstatus | grep -v "inBytes=0" | sed "s/type=ESP.*$/[...]/"
echo done
