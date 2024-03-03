# match: nft ...

/^ nft / b next-nft
b end-nft

:drop-nft
  # read next line (drop current)
  N
  s/^.*\n//
  b match-nft

:next-nft
  # advance to next line (print current, read next)
  n

:match-nft
  # next command?
  /^[a-z][a-z]*#/ b end-nft
  /^[a-z][a-z]* #/ b end-nft

  s/ reqid [1-9][0-9]* / reqid REQID /

b next-nft

:end-nft
