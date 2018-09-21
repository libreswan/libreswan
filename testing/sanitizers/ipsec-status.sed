s/000 secctx-attr-type=.*/000 secctx-attr-type=XXXX/g
s/000 secctx-attr-value=.*/000 secctx-attr-type=XXXX/g
s/\/usr\/local/PATH/g
s/\/usr/PATH/g
s/used [0-9]*s ago/used XXs ago/g
s/RSA Key Aw[^ ]* /RSA Key AwXXXXXXX /g
s/ECDSA Key [^ ]* /ECDSA Key BXXXXXXXX /g

s/esp\.[a-z0-9]\{1,8\}@/esp.ESPSPIi@/g
s/ah\.[a-z0-9]\{1,8\}@/ah.AHSPIi@/g
s/comp\.[a-z0-9]\{1,8\}@/comp.COMPSPIi@/g
