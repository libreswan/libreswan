# match: ip addr ...

/^ ip addr/ b match
b end

:match

  # print and read
  n
  /^[a-z]* #/ b end

  # strip trailing spaces
  s/ $//

b match

:end
