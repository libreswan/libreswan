# match: ipsec stop

/ ipsec stop/ b next-ipsec-stop

b end-ipsec-stop

:drop-ipsec-stop
  # read next line (drop current)
  N
  s/^.*\n//
  b match-ipsec-stop

:next-ipsec-stop
  # advance to next line (print current, read next)
  n

:match-ipsec-stop
  # next command?
  /^[a-z][a-z]*#/ b end-ipsec-stop
  /^[a-z][a-z]* #/ b end-ipsec-stop

  # FreeBSD: Waiting for PIDS: 1192.
  /Waiting for PIDS: / s/[0-9][0-9]*/PID/

b next-ipsec-stop

:end-ipsec-stop
