# match random policy output

/ ipsec _kernel policy/ b next-ipsec-kernel-policy
/^ ip xfrm policy$/ b next-ipsec-kernel-policy
/^ ip -4 xfrm policy$/ b next-ipsec-kernel-policy
/^ ip -6 xfrm policy$/ b next-ipsec-kernel-policy

b end-ipsec-kernel-policy

:drop-ipsec-kernel-policy
  # read next line (drop current)
  N
  s/^.*\n//
  b match-ipsec-kernel-policy

:next-ipsec-kernel-policy
  # advance to next line (print current, read next)
  n

:match-ipsec-kernel-policy
  # next command?
  /^[a-z][a-z]*#/ b end-ipsec-kernel-policy
  /^[a-z][a-z]* #/ b end-ipsec-kernel-policy

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

b next-ipsec-kernel-policy

:end-ipsec-kernel-policy
