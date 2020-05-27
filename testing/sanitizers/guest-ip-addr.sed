# match: ip addr ...

/^ ip addr/ b match
b end

:match

  # print current; read next
  n

:next

  /^[a-z]* #/ b end

  # strip trailing spaces
  s/ $//

  /altname / { N; s/^.*\n//; b next }

b match

:end
