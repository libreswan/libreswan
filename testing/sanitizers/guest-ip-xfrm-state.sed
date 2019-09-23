# match: ip (|-[46]) xfrm state ...

/^ ip xfrm state/ b match
/^ ip -4 xfrm state/ b match
/^ ip -6 xfrm state/ b match
b end

:match

  # print and read next line

  n
  /^[a-z]* #/ b end

  # some versions print the flag 80, others print esp
  /replay-window [0-9]* flag / s/\( flag.*\) 80/\1 esn/

  # fix up keys and other magic numbers; see also ipsec look
  s/ spi 0x[^ ]* / spi 0xSPISPI /g
  s/ reqid [0-9][0-9]* / reqid REQID /g

  # too many exceptions; use gnu extensions
  / sport \(22\|80\|88\|222\|333\|666\|667\|1234\|1701\|2500\|4300\|4500\|6081\) /! {
    s/ sport [0-9]\+ dport/ sport SPORT dport/g;
  }

  s/\tauth\(.*\) 0x[^ ]* \(.*\)$/\tauth\1 0xHASHKEY \2/g
  s/\tenc \(.*\) 0x.*$/\tenc \1 0xENCKEY/g
  s/\taead \(.*\) 0x[^ ]*\( .*\)$/\taead \1 0xENCAUTHKEY\2/g

b match

:end
