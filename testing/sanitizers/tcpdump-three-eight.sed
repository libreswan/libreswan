s/icmp\([0-9 ]*\):/icmp:/
s/\(.*\)echo request seq .*\(.*\)/\1echo request (DF)\2/
s/\(.*\)echo request, id .*, seq .*\(.*\)/\1echo request (DF)\2/
s/\(.*\)echo reply, id .*, seq .*\(.*\)/\1echo reply (DF)\2/
s/\.isakmp/.500/g
s/^IP //
s/: IP /: /
s/icmp:/ICMP/g
s/icmp \d:/ICMP/g
s/, length \d//g
s/echo reply seq .*/echo reply (DF)/
