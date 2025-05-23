# match random policy output

/ ipsec _kernel policy/,/^[a-z][a-z]* #/ {

  # setkey -DP

  s/\([ \t]\)pid=[1-9][0-9]*/\1pid=PID/

  # ipsecctl

  s/\(authkey 0x\)[a-f0-9]*/\1X...X/
  /key_auth:/ s/: [a-f0-9]*$/: X...X/
  /lifetime_cur:/ s/ add [1-9][0-9]*/ add NNNNNNNNNN/
  /lifetime_cur:/ s/ first [1-9][0-9]*/ first NNNNNNNNNN/
  /lifetime_soft:/ s/ bytes [1-9][0-9]* / bytes NNNNNNNNNN /
  /lifetime_soft:/ s/ add [1-9][0-9]* / add NNNN /
  /lifetime_lastuse:/ s/ first [1-9][0-9]*/ first NNNNNNNNNN/
  s/ spi 0x[0-9a-f]\{8\} / spi 0xSPISPI /

  # ip xfrm policy

  / spi 0x00000000 /! s/ spi 0x[^ ]* / spi 0xSPISPI /g
  s/ reqid [1-9][0-9]* / reqid REQID /g
  # dir ... priority 2080718 ptype ...
  s/ priority [1-9][0-9]* ptype / priority PRIORITY ptype /

}
