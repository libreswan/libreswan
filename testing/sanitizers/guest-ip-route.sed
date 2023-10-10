# match: ip (|-[46]) route ...

/^ ip route/ b match-ip-route
/^ ip -4 route/ b match-ip-route
/^ ip -6 route/ b match-ip-route
b end-ip-route

:match-ip-route

  # print and read
  n
  /^[a-z]* #/ b end-ip-route

  # some versions embed spaces in the middle or end of the output
  s/  / /g
  s/ $//

b match-ip-route

:end-ip-route


