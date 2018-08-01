# match: ip (|-[46]) xfrm state ...

/^ ip xfrm state/ b match
/^ ip -4 xfrm state/ b match
/^ ip -6 xfrm state/ b match
b end

:match

  # print and read next line

  n
  /^[a-z]* #/ b end

  # some versions print the flag 80, others print esp
  /replay-window [0-9]* flag / s/\( flag.*\) 80/\1 esn/

b match

:end
