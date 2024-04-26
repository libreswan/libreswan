s/^pluto\[[0-9]*\]: /pluto[PID]: /
s=^\(pluto\[PID\]: Starting Pluto (Libreswan Version \).*)=\1VERSION)=
s/^\(Starting Pluto (Libreswan Version \).*$/\1)/
s/started helper pid=.* (fd:.*)/started helper pid=999 (fd:9)/
s/Plutorun started on .*/Plutorun started on DATE/
s/@(#) built on .* .* .* by .*@.*/@(#) built on DATE by PERSON/
s/\(received Delete SA\)(0x.*)\( payload: deleting IPsec State #\).*/\1(0xSPI1SPI1)\2NUM/
/ERROR: asynchronous network error report/d
/byte . of ISAKMP Hash Payload must be zero, but is not/d
/next payload type of ISAKMP Hash Payload has an unknown value: /d
/extra debugging enabled for connection:/d
#
s/^SElinux=.*/SElinux=XXXXX/
