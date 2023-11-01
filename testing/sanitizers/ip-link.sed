# match random policy output

/^ ip -d link / b match-ip-link
b end-ip-link

:match-ip-link

  # print and read next line
  n
  /^[a-z]* #/ b end-ip-link

  s/ tso_max_size .*$//

b match-ip-link

:end-ip-link
