# match: setkey ...

/^ setkey / b match
b end

:match

  # print and read next line
  n
  /^[a-z]* #/ b end

  s/\([ \t]\)[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]/\tXXXXXXXX/g

  s/\([ \t]\)pid=[1-9][0-9]*/\1pid=PID/
  s/\([ \t]\)spi=[1-9][0-9]*(0x[^)]*)/\1spi=SPISPI(0xSPISPI)/
  s/\([ \t]\)diff: [0-9]*/\1diff: N/

b match

:end
