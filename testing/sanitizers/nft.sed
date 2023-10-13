# match: nft ...

/^ nft / b match-nft
b end-nft

:match-nft

  # print current; read next
  n
  /^[a-z]* #/ b end-nft

:next-nft

  s/ reqid [1-9][0-9]* / reqid REQID /

b match-nft

:end-nft
