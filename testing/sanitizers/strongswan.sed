# XXX: This optional sanitizer should be rewritten so that it only
# applies to strongswan commands.  That way it can be run
# unconditionally.  As things stand it edits stuff it really has no
# business editing.

s/^\(Starting strongSwan \)\(.*\)\( IPsec.*\)$/\1X.X.X\3/g
s/^\(Status of IKE charon daemon (strongSwan \).*):$/\1VERSION):/g
s/\(  uptime: \)\([0-9]*\)\( second[s]*\)\(, since \)\(.*\)$/\1XXX second\4YYY/g
s/\(  uptime: \)\([0-9]*\)\( minute[s]*\)\(, since \)\(.*\)$/\1XXX minute\4YYY/g
s/  malloc: sbrk [0-9]*, mmap [0-9]*, used [0-9]*, free [0-9]*$/  malloc sbrk XXXXXX,mmap X, used XXXXXX, free XXXXX/g
s/^\(.* ESTABLISHED \)\([0-9]*\)\( second[s]*\)\( ago.*\)$/\1XXX second\4/g
#s/^\(.* IKEv[12] SPIs: \)\(.*_i\)+*\( .*_r.\)\(,.*\)$/\1SPISPI_i SPISPI_r\4/g
s/SPIs: [0-9a-z]*_i\([\*]*\) [0-9a-z]*_r\([\*]*\)/SPIs: SPISPI_i\1 SPISPI_r\2/g
s/^\(.*  INSTALLED, T[A-Z]*, .* SPIs: \)\(.*_i \)\(.*_o\)$/\1SPISPI_i SPISPI_o/g
s/^\(scheduling reauthentication in \)\([0-9]*s\)/\1XXXs/g
s/^\(maximum IKE_SA lifetime \)\([0-9]*s\)/\1XXXs/g
s/[0-9]* bytes_i ([0-9]* pkts, [0-9X]*s ago), [0-9X]* bytes_o ([0-9X]* pkts, [0-9X]*s ago), rekeying in [0-9X]* minutes/XXX bytes_i (XX pkts, XXs ago), XXX bytes_o (XX pkts, XXs ago), rekeying in XX minutes/g
s/[0-9]* bytes_i ([0-9]*s ago), [0-9]* bytes_o ([0-9]* pkts, [0-9]*s ago), rekeying in [0-9]* minutes/XXX bytes_i (xxs ago), XX bytes_o (XX pkts, XXs ago), rekeying in XX minutes/g
s/[0-9]* bytes_i, [0-9]* bytes_o, rekeying in [0-9]* minutes/XX bytes_i, XX bytes_o, rekeying in XX minutes/g
s/([0-9]* bytes)/(XXX bytes)/g
s/\(INSTALLED, T[A-Z]*, .* in UDP SPIs: \)[a-z0-9]*_i [a-z0-9]*_o/\1SPISPI_i SPISPI_o/g
/^  worker threads: .*$/d
/^  loaded plugins: .*$/d
s/QUICK_MODE request [0-9]* /QUICK_MODE request 0123456789 /g
s/QUICK_MODE response [0-9]* /QUICK_MODE response 0123456789 /g
# strip out our own changing vendor id
s/received unknown vendor ID: 40:48.*/received unknown vendor ID: LIBRESWAN/g
s/rekeying in [0-9]* minutes/rekeying in XX minutes/g
s/ESTABLISHED [0-9]* seconds ago/ESTABLISHED XXX seconds ago/g
s/established with SPIs .* and /established with SPIs SPISPI_i SPISPI_o and /
s/received AUTH_LIFETIME of [0-9]*s, scheduling reauthentication in [0-9]*s/received AUTH_LIFETIME of XXXXs, scheduling reauthentication in XXXXs/
s/server requested EAP_MD5 authentication.*$/server requested EAP_MD5 authentication XXX/g
