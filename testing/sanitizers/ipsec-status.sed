s/^secctx-attr-type=.*/secctx-attr-type=XXXX/g
s/^secctx-attr-value=.*/secctx-attr-type=XXXX/g
s/\/usr\/local/PATH/g
s/\/usr/PATH/g
s/used [0-9]*s ago/used XXs ago/g
s/RSA Key A[wQ][^ ]* /RSA Key AwXXXXXXX /g
s/ECDSA Key [^ ]* /ECDSA Key BXXXXXXXX /g

# Try not to sanitize {esp,ah,comp}.0@
# For some reason IPv6 uses ':' and not '.'
# why the bonus i?

s/esp\([.:]\)[a-z1-9]@/esp\1ESPSPIi@/g
s/ah\([.:]\)[a-z1-9]@/ah\1AHSPIi@/g
s/comp\([.:]\)[a-z1-9]@/comp\1COMPSPIi@/g

s/esp\([.:]\)[a-z0-9]\{2,8\}@/esp\1ESPSPIi@/g
s/ah\([.:]\)[a-z0-9]\{2,8\}@/ah\1AHSPIi@/g
s/comp\([.:]\)[a-z0-9]\{2,8\}@/comp\1COMPSPIi@/g

#

s/ SPI [0-9a-f][0-9a-f]* / SPI SPISPI /

# don't change seq number "0" entries
s/seq in:[1-9][0-9]* out:[0-9]*/seq in:XXXXX out:YYYYY/g

# XXX: this shouldn't be sanitizing out audit_log=yes
/pluto_version=/d
s/^SElinux=.*/SElinux=XXXXX/

/ session resume ticket: / {
  s/ length: [0-9]* bytes;/ length: B bytes;/
  s/ expires-in: [0-9]*s;/ expires-in: Ns;/
}
