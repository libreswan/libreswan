#s/^\[[0-9]\]* [0-9]*$/[X] XXXX/
# all backgrounding
s/^\[[0-9]\] [0-9]*$/[x] PID/
# nc -4 -l 192.1.2.23 222 &
#[1] 2209
/^ nc .*\&$/ {N; s/^ nc \(.*\&\)\n\[[0-9]*\] [0-9]*$/ nc \1\n[B] PID/g}
# versions of tools used
/^ *Electric Fence.*$/d
/^.*anti-replay context:.*$/d

s/ike-scan \(.*\) with/ike-scan XX with/
s/Ending ike-scan \(.*\):/ Ending ike-scan XX:/
s/conntrack v[0-9]*\.[0-9]*\.[0-9]* /conntrack vA.B.C /
s/ip_vti0@NONE: <NOARP> mtu [0-9]* /ip_vti0@NONE: <NOARP> mtu XXXX /
# this prevents us seeing race conditions between namespaces / kvm
/^.*Terminated.*ip -s xfrm monitor.*$/d
/^.*for ASN.1 blob for method.*$/d
# nss picks up softhsm/opendnssec token?
/^.* for token "OpenDNSSEC".*$/d
/^Relabeled \/testing.*$/d
# some things are different on Debian/Ubuntu, and we dont really need to see those for testing
/^nssdir=.*$/d

# timing info from the log
s/last_contact=0->[0-9]*\.[0-9]*/last_contact=0->XX.XXX/g
s/last_contact=[0-9]*\.[0-9]*->[0-9]*\.[0-9]*/last_contact=XX.XXX->XX.XXX/g
s/last_contact=[0-9]*\.[0-9]*/last_contact=XX.XXX/g

# TCP sockets
s/ socket [0-9][0-9]*: / socket XX: /g

s/encap type 7 sport/encap type espintcp sport/g
s/unbound-control.[0-9]*:[0-9]*./unbound-control[XXXXXX:X] /g 
# softhsm - pkcs-uri ephemerals
s/serial=[^;]*;token=libreswan/serial=XXXXXXXX;token=libreswan/g
s/and is reassigned to slot .*$/and is reassigned to slot XXXXX/g

# prevent stray packets from changing counters
s/\t 00000000 00000000 00000000 .*$/\t 00000000 00000000 00000000 XXXXXXXX /g
s/\t seq-hi 0x0, seq [^,]*, oseq-hi 0x0, oseq .*$/\t seq-hi 0x0, seq 0xXX, oseq-hi 0x0, oseq 0xXX/g

# filter out ipsec auto deprecation warning
/^WARNING: ipsec auto has been deprecated/d

# debug details aren't interesting
s/^debug:.*/debug .../
