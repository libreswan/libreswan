s/^secctx-attr-type=.*/secctx-attr-type=XXXX/g
s/^secctx-attr-value=.*/secctx-attr-type=XXXX/g
s/\/usr\/local/PATH/g
s/\/usr/PATH/g
s/used [0-9]*s ago/used XXs ago/g
s/RSA Key Aw[^ ]* /RSA Key AwXXXXXXX /g
s/ECDSA Key [^ ]* /ECDSA Key BXXXXXXXX /g

# Try not to sanitize esp.0@ et.al.

s/esp\.[a-z1-9]@/esp.ESPSPIi@/g
s/ah\.[a-z1-9]@/ah.AHSPIi@/g
s/comp\.[a-z1-9]@/comp.COMPSPIi@/g

s/ SPI [a-z0-9][a-z0-9]* / SPI SPISPI /

s/esp\.[a-z0-9]\{2,8\}@/esp.ESPSPIi@/g
s/ah\.[a-z0-9]\{2,8\}@/ah.AHSPIi@/g
s/comp\.[a-z0-9]\{2,8\}@/comp.COMPSPIi@/g

# don't change seq number "0" entries
s/seq in:[1-9][0-9]* out:[0-9]*/seq in:XXXXX out:YYYYY/g

# XXX: this shouldn't be sanitizing out audit_log=yes
/pluto_version=/d