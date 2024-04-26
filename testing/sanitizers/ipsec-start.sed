# match: ipsec start

/ ipsec start/ b next-ipsec-start
/ ipsec pluto/ b next-ipsec-start

b end-ipsec-start

:drop-ipsec-start
  # read next line (drop current)
  N
  s/^.*\n//
  b match-ipsec-start

:next-ipsec-start
  # advance to next line (print current, read next)
  n

:match-ipsec-start
  # next command?
  /^[a-z][a-z]*#/ b end-ipsec-start
  /^[a-z][a-z]* #/ b end-ipsec-start

  s/^\(Starting Pluto (Libreswan Version\) .* pid:.*$/\1 ...) pid:PID/
  s/^\(operating system\): .*/\1: .../

  # no matter what you do linux sometimes emits these
  /Starting .*mipsec.service.* - Internet … (IKE) Protocol Daemon for IPsec/ {
  	    b drop-ipsec-start
  }
  /Started .*mipsec.service.* - Internet K…ge (IKE) Protocol Daemon for IPsec/ {
  	    b drop-ipsec-start
  }

b next-ipsec-start

:end-ipsec-start
