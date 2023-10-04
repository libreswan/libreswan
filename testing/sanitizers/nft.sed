# match: nft ...

/^ nft / b nft-match
b nft-end

:nft-match

  # print current; read next
  n

:nft-next

  s/ reqid [1-9][0-9]* / reqid REQID /

b nft-match

:nft-end
