# match: ip link ...

/^ ip link/ b match-ip-link
/^ ip -d link/ b match-ip-link
b end-ip-link

:match-ip-link

  # print current; read next
  n

:next-ip-link

  /^[a-z]* #/ b end-ip-link

  # strip trailing spaces
  s/ $//
  # and junk
  s/ qlen 1000$//

  # append next line; delete current; try again
  /altname / {
  	   N
	   s/^.*\n//
	   b next-ip-link
  }

b match-ip-link

:end-ip-link
