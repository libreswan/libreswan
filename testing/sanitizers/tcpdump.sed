# old unused rules commented out
#s/icmp\([0-9 ]*\):/icmp:/
#s/\(.*\)echo request seq .*\(.*\)/\1echo request (DF)\2/
#s/\(.*\)echo request, id .*, seq .*\(.*\)/\1echo request (DF)\2/
#s/\(.*\)echo reply, id .*, seq .*\(.*\)/\1echo reply (DF)\2/
#s/\.isakmp/.500/g
#s/^IP //
#s/: IP /: /
#s/icmp:/ICMP/g
#s/icmp \d:/ICMP/g
#s/, length \d//g
#s/echo reply seq .*/echo reply (DF)/

# nflog
# 15:49:06.782887 IP 192.0.1.254 > 192.0.2.254: ICMP echo request, id 1892, seq 1, length 64
s/[0-9][0-9]:[0-9][0-9]:[0-9][0-9]\.[0-9]* IP /IP /g
s/, id [0-9]*, seq/, id XXXX, seq/g
