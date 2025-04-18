# match: nft ...

/^ nft /,/^[a-z][a-z]* #$/ {

  s/ reqid [1-9][0-9]* / reqid REQID /

}
