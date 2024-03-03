# match: ip (|-[46]) route ...

/^ ip route/ b next-ip-route
/^ ip -4 route/ b next-ip-route
/^ ip -6 route/ b next-ip-route
b end-ip-route

:drop-ip-route
  # read next line (drop current)
  N
  s/^.*\n//
  b match-ip-route

:next-ip-route
  # advance to next line (print current, read next)
  n

:match-ip-route
  # next command?
  /^[a-z][a-z]*#/ b end-ip-route
  /^[a-z][a-z]* #/ b end-ip-route

  # some versions embed spaces in the middle or end of the output
  s/  / /g
  s/ $//

b next-ip-route

:end-ip-route


