# match: ip (|-[46]) route ...

/^ ip route/ b match
/^ ip -4 route/ b match
/^ ip -6 route/ b match
b end

:match

  # print and read
  n
  /^[a-z]* #/ b end

  # some versions embed spaces in the middle or end of the output
  s/  / /g
  s/ $//

b match

:end
