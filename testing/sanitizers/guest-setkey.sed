# match: setkey ...

/^ setkey / b match
b end

:match

  # print and read next line
  n
  /^[a-z]* #/ b end

  s/ [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]/ XXXXXXXX/g

  s/ pid=[1-9][0-9]*/ pid=PID/
  s/ spi=[1-9][0-9]*(0x[^)]*)/ spi=SPISPI(0xSPISPI)/
  s/ diff: [0-9]*/ diff: N/

b match

:end
