# match: cp .. ...

/^ cp / b match-cp
b end-cp

:match-cp

  # print and read next line
  n
  /^[a-z]* #/ b end-cp

  # f22: cp: cannot stat ‘/tmp/xfrm-monitor.out’: No such file or directory
  # f28: cp: cannot stat '/tmp/xfrm-monitor.out': No such file or directory
  s/‘/'/g
  s/’/'/g
  s/'/'/g
  s/`/'/g

b match-cp

:end-cp
