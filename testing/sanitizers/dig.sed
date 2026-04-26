# match: dig ...

/^\(\|[a-z][a-z]*#\) dig /,/^[a-z][a-z]* #$/ {

  s/ id: [1-9][0-9]*$/ id: DNSID/
  s/Query time: [1-9][0-9]* msec/Query time: MS msec/

}
