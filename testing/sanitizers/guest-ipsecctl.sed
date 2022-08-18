# match: setkey ...

/^ ipsecctl / b match
b end

:match

  # print current, then read next line
  n
  /^[a-z]* #/ b end

  s/\(authkey 0x\)[a-f0-9]*/\1X...X/
  /key_auth:/ s/: [a-f0-9]*$/: X...X/

  /lifetime_cur:/ s/ add [1-9][0-9]*/ add NNNNNNNNNN/
  /lifetime_cur:/ s/ first [1-9][0-9]*/ first NNNNNNNNNN/
  /lifetime_soft:/ s/ bytes [1-9][0-9]* / bytes NNNNNNNNNN /
  /lifetime_soft:/ s/ add [1-9][0-9]* / add NNNN /
  /lifetime_lastuse:/ s/ first [1-9][0-9]*/ first NNNNNNNNNN/

  s/ spi 0x[0-9a-f]\{8\} / spi 0xSPISPI /

b match

:end
