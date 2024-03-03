# match: ip addr ...

/^ ip addr/ b next-ip-addr

b end-ip-addr

:drop-ip-addr
  # read next line (drop current)
  N
  s/^.*\n//
  b match-ip-addr

:next-ip-addr
  # advance to next line (print current, read next)
  n

:match-ip-addr
  # next command?
  /^[a-z][a-z]*#/ b end-ip-addr
  /^[a-z][a-z]* #/ b end-ip-addr

  # strip trailing spaces
  s/ $//

  # strip trailing stuff
  s/ qlen 1000$//

  # drop line
  /altname / {
  	   b drop-ip-addr
  }

b next-ip-addr

:end-ip-addr
