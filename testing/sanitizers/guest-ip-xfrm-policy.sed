# match: ip (|-[46]) xfrm policy ...

/^ ip xfrm policy/ b match
/^ ip -4 xfrm policy/ b match
/^ ip -6 xfrm policy/ b match
b end

:match

  # print and read next line
  n
  /^[a-z]* #/ b end

  s/ spi 0x[^ ]* / spi 0xSPISPI /g
  s/ reqid [0-9][0-9]* / reqid REQID /g

b match

:end
