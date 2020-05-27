# match: ip link ...

/^ ip link/ b match
b end

:match

  # print current; read next
  n

:next

  /^[a-z]* #/ b end

  # strip trailing spaces
  s/ $//

  # append next line; delete current; try again
  /altname / { N; s/^.*\n//; b next }

b match

:end
