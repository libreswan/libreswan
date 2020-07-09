#s/^\[[0-9]\]* [0-9]*$/[X] XXXX/
# filter out the backgrounding of tcpdump
# tcpdump -i lo -n -c 6 2> /dev/null &
# [1] 1652
/^ tcpdump .*\&$/ {N; s/^ tcpdump \(.*\&\)\n\[[0-9]*\] [0-9]*$/ tcpdump \1\n[B] PID/g}
# why not just all backgrounding
s/^\[[0-9]\] [0-9]*$/[x] PID/
# nc -4 -l 192.1.2.23 222 &
#[1] 2209
/^ nc .*\&$/ {N; s/^ nc \(.*\&\)\n\[[0-9]*\] [0-9]*$/ nc \1\n[B] PID/g}
/^ (cd \/tmp \&\& xl2tpd.*/ {N; s/^ \((cd \/tmp \&\& xl2tpd.*\)\n\[[0-9]*\] [0-9]*$/ \1\n[B] PID/g}
# versions of tools used
s/SSH-2.0-OpenSSH_.*$/SSH-2.0-OpenSSH_XXX/
/^ *Electric Fence.*$/d
/^.*anti-replay context:.*$/d
s/add bare shunt 0x[^ ]* /add bare shunt 0xPOINTER /
s/delete bare shunt 0x[^ ]* /delete bare shunt 0xPOINTER /
s/ike-scan \(.*\) with/ike-scan XX with/
s/Ending ike-scan \(.*\):/ Ending ike-scan XX:/
s/conntrack v[0-9]*\.[0-9]*\.[0-9]* /conntrack vA.B.C /
s/ip_vti0@NONE: <NOARP> mtu [0-9]* /ip_vti0@NONE: <NOARP> mtu XXXX /
# this prevents us seeing race conditions between namespaces / kvm
/^.*Terminated.*ip -s xfrm monitor.*$/d
# sshd on fedora 30 and 31 have slightly different error msgs
s/^Protocol mismatch\.$/Invalid SSH identification string./g
/^.*for ASN.1 blob for method.*$/d
# nss picks up softhsm/opendnssec token?
/^.* for token "OpenDNSSEC".*$/d
/^Relabeled \/testing.*$/d
# some things are different on Debian/Ubuntu, and we dont really need to see those for testing
/000 nssdir=.*$/d
/000 dnssec-rootkey-file=.*$/d
# timing info from the log
s/last_contact=0->[0-9]*\.[0-9]*/last_contact=0->XX.XXX/g
s/last_contact=[0-9]*\.[0-9]*/last_contact=XX.XXX/g
# TCP sockets
s/from socket [0-9]* /from socket XX /g
s/IMPAIR: TCP: socket [0-9]* /IMPAIR: TCP: socket XX /g

