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
