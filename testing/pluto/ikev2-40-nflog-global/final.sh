ipsec look
killall -9 tcpdump
cp  /tmp/nflog-50.pcap nflog-50.pcap
tcpdump  -r OUTPUT/nflog-50.pcap |wc -l
: ==== cut ====
ipsec auto --status
: ==== tuc ====
if [ -n "`ls /tmp/core* 2>/dev/null`" ]; then echo CORE FOUND; mv /tmp/core* OUTPUT/; fi
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
