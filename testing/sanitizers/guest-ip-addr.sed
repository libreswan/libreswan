# match: ip addr ...

/^ ip addr/ b match-ip-addr
b end-ip-addr

:match-ip-addr

  # print current; read next
  n

:next-ip-addr

  # next line; exit
  /^[a-z]* #/ b end-ip-addr

  # strip trailing spaces
  s/ $//

  # strip trailing stuff
  s/ qlen 1000$//

  # append next line; delete current; try again
  /altname / {
  	   N
	   s/^.*\n//
	   b next-ip-addr
  }

b match-ip-addr

:end-ip-addr
