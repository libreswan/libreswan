s/^\(Starting strongSwan \)\(.*\)\( IPsec.*\)$/\1X.X.X\3/g
s/^\(Status of IKE charon daemon (strongSwan \).*):$/\1VERSION):/g
s/\(  uptime: \)\([0-9]*\)\( seconds, since \)\(.*\)$/\1XXX\3YYY/g
s/  malloc: sbrk [0-9]*, mmap [0-9]*, used [0-9]*, free [0-9]*$/  malloc sbrk XXXXXX,mmap X, used XXXXXX, free XXXXX/g
s/^\(.* ESTABLISHED \)\([0-9]*\)\( seconds ago.*\)$/\1XXX\3/g
s/^\(.* IKEv[12] SPIs: \)\(.*_i\) \(.*_r.\)\(, .*\)$/\1SPISPI_i SPISPI_r\4/g
s/^\(.*  INSTALLED, TUNNEL, ESP SPIs: \)\(.*_i \)\(.*_o\)$/\1SPISPI_i SPISPI_o/g
s/^\(scheduling reauthentication in \)\([0-9]*s\)/\1XXXs/g
s/^\(maximum IKE_SA lifetime \)\([0-9]*s\)/\1XXXs/g
s/[0-9]* bytes_i ([0-9]*s ago), [0-9]* bytes_o ([0-9]* pkts, [0-9]*s ago), rekeying in [0-9]* minutes/XXX bytes_i (xxs ago), XX bytes_o (XX pkts, XXs ago), rekeying in XX minutes/g
