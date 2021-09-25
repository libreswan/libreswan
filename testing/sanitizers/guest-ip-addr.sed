# match: ip addr ...

/^ ip addr/ b match
b

:match

  # print current; read next
  n

:next

  # next line; exit
  /^[a-z]* #/ b

  # strip trailing spaces
  s/ $//

  # strip trailing stuff
  s/ qlen 1000$//

  # append next line; delete current; try again
  /altname / { N; s/^.*\n//; b next }

b match
