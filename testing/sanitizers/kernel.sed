# Note: kernel messages aren't just at the start of the line.  Instead
# they get concatenated to what ever is there, and that needs to be
# preserved.  Hence a join is used.

:start

# [ 111.628924] -> [00.00]
s/\[\s\+[0-9]\+\.[0-9]\+\] /[ 00.00] /

# Use time to anchor string (can't use ^ as may not be at start
/\[ 00.00] AVX or AES-NI instructions are not detected/ b join
/\[ 00.00] IPv4 over IPsec tunneling driver/ b join
/\[ 00.00] IPsec XFRM device driver/ b join
/\[ 00.00] alg: No test for / b join
/\[ 00.00] tun: Universal TUN\/TAP device driver/ b join
/\[ 00.00] SELinux: / b join
/\[ 00.00] gre: GRE over IPv4 demultiplexor driver/ b join
/\[ 00.00] ip_gre: GRE over IPv4 tunneling driver/ b join
/\[ 00.00] PPP / b join
/\[ 00.00] NET: / b join
/\[ 00.00] hrtimer: interrupt took / b join

b

:join

# join the next line
N
# and zap the kernel error message
s/\[ 00.00] [^\n]*\n//

b start
