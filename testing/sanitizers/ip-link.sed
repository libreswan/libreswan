# match: ip link ...

/^ ip link/ b next-ip-link
/^ ip -d link/ b next-ip-link

b end-ip-link

:drop-ip-link
  # read next line (drop current)
  N
  s/^.*\n//
  b match-ip-link

:next-ip-link
  # advance to next line (print current, read next)
  n

:match-ip-link
  # next command?
  /^[a-z][a-z]*#/ b end-ip-link
  /^[a-z][a-z]* #/ b end-ip-link

  # strip trailing spaces
  s/ $//
  # and junk
  s/ qlen 1000$//

  # append next line; delete current; try again
  /altname / {
  	   b drop-ip-link
  }

b next-ip-link

:end-ip-link
