# use a static source port just to prevent false positive on larval state port
echo TRIGGER-OE | nc -s 192.1.3.209 -p 42599 192.1.2.23 22
# wait on OE retransmits and rekeying
sleep 5
# should show tunnel and no shunts, and non-zero traffic count
# workaround for diff err msg between fedora versions resulting in diff byte count
ipsec whack --trafficstatus | grep -v "inBytes=0" | sed "s/type=ESP.*$/[...]/"
ipsec whack --shuntstatus
echo done
